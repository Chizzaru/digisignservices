package com.github.ws_ncip_pnpki.service;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.element.Image;
import com.itextpdf.signatures.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.*;

@Service
public class PdfSigningService_working_20251020_1626 {
    @Value("${pdf.signing.output-dir:./signed-documents}")
    private String outputDir;

    @Value("${pdf.signing.tsa.url:}")
    private String tsaUrl;

    @Value("${pdf.signing.tsa.username:}")
    private String tsaUsername;

    @Value("${pdf.signing.tsa.password:}")
    private String tsaPassword;

    @Value("${pdf.signing.tsa.enabled:false}")
    private boolean tsaEnabled;

    private PDDocument currentDoc;

    public static class SignaturePlacement {
        public int pageNumber;
        public float x;
        public float y;
        public float width;
        public float height;

        public SignaturePlacement() {}

        public SignaturePlacement(int pageNumber, float x, float y, float width, float height) {
            this.pageNumber = pageNumber;
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
        }

        public int getPageNumber() { return pageNumber; }
        public void setPageNumber(int pageNumber) { this.pageNumber = pageNumber; }
        public float getX() { return x; }
        public void setX(float x) { this.x = x; }
        public float getY() { return y; }
        public void setY(float y) { this.y = y; }
        public float getWidth() { return width; }
        public void setWidth(float width) { this.width = width; }
        public float getHeight() { return height; }
        public void setHeight(float height) { this.height = height; }
    }

    public String signPdfMultiPage(
            MultipartFile pdfDocument,
            MultipartFile signatureImage,
            MultipartFile certificateFile,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String password,
            String location) throws Exception {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream certInputStream = certificateFile.getInputStream()) {
            keyStore.load(certInputStream, password.toCharArray());
        }

        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);

        File tempPdfFile = File.createTempFile("temp_pdf_", ".pdf");
        File tempSignatureFile = File.createTempFile("temp_sig_", getFileExtension(signatureImage.getOriginalFilename()));
        File tempStampedPdf = File.createTempFile("temp_stamped_", ".pdf");

        pdfDocument.transferTo(tempPdfFile);
        signatureImage.transferTo(tempSignatureFile);

        loadPdf(tempPdfFile);

        if (!tempSignatureFile.exists() || tempSignatureFile.length() == 0) {
            throw new Exception("Signature image file is empty or not created");
        }

        String outputFileName = "signed_" + UUID.randomUUID() + ".pdf";
        File outputFile = new File(outputDir, outputFileName);

        try {
            int digitalSignaturePage = placements.get(0).pageNumber;

            System.out.println("\n=== STEP 1: Adding Visual Signatures ===");
            System.out.println("   Digital signature will be on page: " + digitalSignaturePage);

            addVisualSignaturesToPages(
                    tempPdfFile,
                    tempStampedPdf,
                    placements,
                    digitalSignaturePage,
                    canvasWidth,
                    canvasHeight,
                    tempSignatureFile,
                    chain,              // ← Added this parameter
                    location,
                    "Signed Authorization"
            );

            System.out.println("\n=== STEP 2: Applying Digital Signature ===");
            signPdfWithDigitalSignature(
                    tempStampedPdf,
                    outputFile,
                    privateKey,
                    chain,
                    placements,
                    canvasWidth,
                    canvasHeight,
                    location,
                    tempSignatureFile
            );

            System.out.println("\n✅ Multi-page signing completed successfully!");
            return outputFileName;

        } finally {
            if (tempPdfFile.exists()) tempPdfFile.delete();
            if (tempSignatureFile.exists()) tempSignatureFile.delete();
            if (tempStampedPdf.exists()) tempStampedPdf.delete();
            if (currentDoc != null) currentDoc.close();
        }
    }

    private Rectangle calculateSignatureRectangle(
            SignaturePlacement placement,
            float canvasWidth,
            float canvasHeight,
            float pdfPageWidth,
            float pdfPageHeight) {

        float scaleX = pdfPageWidth / canvasWidth;
        float scaleY = pdfPageHeight / canvasHeight;

        float pdfX = placement.x * scaleX;
        float pdfWidth = placement.width * scaleX;
        float pdfHeight = placement.height * scaleY;
        float pdfY = pdfPageHeight - (placement.y * scaleY) - pdfHeight;

        pdfX = Math.max(0, Math.min(pdfX, pdfPageWidth - pdfWidth));
        pdfY = Math.max(0, Math.min(pdfY, pdfPageHeight - pdfHeight));
        pdfWidth = Math.min(pdfWidth, pdfPageWidth - pdfX);
        pdfHeight = Math.min(pdfHeight, pdfPageHeight - pdfY);

        return new Rectangle(pdfX, pdfY, pdfWidth, pdfHeight);
    }

    private void addVisualSignaturesToPages(
            File srcPdf,
            File destPdf,
            List<SignaturePlacement> placements,
            int digitalSignaturePage,
            float canvasWidth,
            float canvasHeight,
            File signatureImageFile,
            Certificate[] chain,
            String location,
            String reason) throws Exception {

        System.out.println("🖼️  Adding visual signatures");
        System.out.println("   Excluding page: " + digitalSignaturePage);

        PdfReader reader = new PdfReader(srcPdf);
        PdfWriter writer = new PdfWriter(destPdf);
        PdfDocument pdfDoc = new PdfDocument(reader, writer);

        try {
            if (!signatureImageFile.exists()) {
                throw new Exception("Signature file not found");
            }

            ImageData imageData = ImageDataFactory.create(signatureImageFile.getAbsolutePath());
            System.out.println("   Image loaded: " + imageData.getWidth() + "x" + imageData.getHeight());

            // Extract signer info from certificate
            String signerName = "Unknown";
            if (chain != null && chain.length > 0) {
                try {
                    java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) chain[0];
                    signerName = cert.getSubjectX500Principal().getName();
                    // Extract CN (Common Name) from the full DN
                    String[] parts = signerName.split(",");
                    for (String part : parts) {
                        if (part.trim().startsWith("CN=")) {
                            signerName = part.trim().substring(3);
                            break;
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Could not extract signer name: " + e.getMessage());
                }
            }

            int added = 0;
            for (int i = 0; i < placements.size(); i++) {
                SignaturePlacement placement = placements.get(i);

                // SKIP the digital signature page
                if (placement.pageNumber == digitalSignaturePage) {
                    System.out.println("\n⏭️  SKIPPING Page " + placement.pageNumber + " (digital signature page)");
                    continue;
                }

                System.out.println("\n📝 Adding to Page " + placement.pageNumber);

                if (placement.pageNumber > pdfDoc.getNumberOfPages() || placement.pageNumber < 1) {
                    System.err.println("   ❌ Invalid page: " + placement.pageNumber);
                    continue;
                }

                com.itextpdf.kernel.pdf.PdfPage page = pdfDoc.getPage(placement.pageNumber);
                Rectangle pageSize = page.getPageSize();

                Rectangle rect = calculateSignatureRectangle(
                        placement,
                        canvasWidth,
                        canvasHeight,
                        pageSize.getWidth(),
                        pageSize.getHeight()
                );

                System.out.println("   Rectangle: X=" + rect.getX() + ", Y=" + rect.getY() +
                        ", W=" + rect.getWidth() + ", H=" + rect.getHeight());

                // Create PdfCanvas for the page
                PdfCanvas pdfCanvas = new PdfCanvas(page);

                // REMOVED: Border drawing code
                // pdfCanvas.saveState();
                // pdfCanvas.setStrokeColor(com.itextpdf.kernel.colors.ColorConstants.BLACK);
                // pdfCanvas.setLineWidth(1);
                // pdfCanvas.rectangle(rect.getX(), rect.getY(), rect.getWidth(), rect.getHeight());
                // pdfCanvas.stroke();
                // pdfCanvas.restoreState();

                // Calculate image area (left side, 40% of width)
                float imageWidth = rect.getWidth() * 0.4f;
                float imageHeight = rect.getHeight();

                // Add signature image on the left
                Image image = new Image(imageData);
                image.scaleToFit(imageWidth - 4, imageHeight - 4);

                // Calculate centered position for image
                float imageX = rect.getX() + 2;
                float imageY = rect.getY() + (rect.getHeight() - image.getImageScaledHeight()) / 2;

                // Add image using canvas positioning
                pdfCanvas.saveState();
                float scaleX = image.getImageScaledWidth() / imageData.getWidth();
                float scaleY = image.getImageScaledHeight() / imageData.getHeight();
                pdfCanvas.concatMatrix(scaleX, 0, 0, scaleY, imageX, imageY);
                pdfCanvas.addImageAt(imageData, 0, 0, false);
                pdfCanvas.restoreState();

                // Add text using page coordinates directly
                com.itextpdf.kernel.font.PdfFont font = com.itextpdf.kernel.font.PdfFontFactory.createFont();
                com.itextpdf.kernel.font.PdfFont boldFont = com.itextpdf.kernel.font.PdfFontFactory.createFont(
                        com.itextpdf.io.font.constants.StandardFonts.HELVETICA_BOLD
                );

                float textX = rect.getX() + imageWidth + 6;
                float textY = rect.getY() + rect.getHeight() - 12;

                // Signer name (bold)
                pdfCanvas.saveState();
                pdfCanvas.beginText();
                pdfCanvas.setFontAndSize(boldFont, 8);
                pdfCanvas.moveText(textX, textY);
                pdfCanvas.showText(signerName);
                pdfCanvas.endText();
                pdfCanvas.restoreState();
                textY -= 12;

                // Reason
                if (reason != null && !reason.isEmpty()) {
                    pdfCanvas.saveState();
                    pdfCanvas.beginText();
                    pdfCanvas.setFontAndSize(font, 7);
                    pdfCanvas.moveText(textX, textY);
                    pdfCanvas.showText("Reason: " + reason);
                    pdfCanvas.endText();
                    pdfCanvas.restoreState();
                    textY -= 10;
                }

                // Location
                if (location != null && !location.isEmpty()) {
                    pdfCanvas.saveState();
                    pdfCanvas.beginText();
                    pdfCanvas.setFontAndSize(font, 7);
                    pdfCanvas.moveText(textX, textY);
                    pdfCanvas.showText("Location: " + location);
                    pdfCanvas.endText();
                    pdfCanvas.restoreState();
                    textY -= 10;
                }

                // Date
                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String dateStr = sdf.format(new Date());
                pdfCanvas.saveState();
                pdfCanvas.beginText();
                pdfCanvas.setFontAndSize(font, 7);
                pdfCanvas.moveText(textX, textY);
                pdfCanvas.showText("Date: " + dateStr);
                pdfCanvas.endText();
                pdfCanvas.restoreState();

                added++;
                System.out.println("   ✅ Added");
            }

            System.out.println("\n✅ Visual signatures added: " + added);

        } finally {
            pdfDoc.close();
        }
    }

    private void signPdfWithDigitalSignature(
            File srcPdf,
            File destPdf,
            PrivateKey privateKey,
            Certificate[] chain,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String location,
            File signatureImageFile) throws Exception {

        System.out.println("🔐 Applying digital signature");

        StampingProperties stampingProperties = new StampingProperties();
        stampingProperties.useAppendMode();

        PdfReader reader = new PdfReader(srcPdf);
        FileOutputStream fos = new FileOutputStream(destPdf);

        try {
            PdfSigner signer = new PdfSigner(reader, fos, stampingProperties);

            String fieldName = "Signature_" + UUID.randomUUID().toString().substring(0, 8);
            signer.setFieldName(fieldName);

            SignaturePlacement primaryPlacement = placements.get(0);

            PdfDocument tempDoc = new PdfDocument(new PdfReader(srcPdf));
            com.itextpdf.kernel.pdf.PdfPage page = tempDoc.getPage(primaryPlacement.pageNumber);
            Rectangle pageSize = page.getPageSize();
            tempDoc.close();

            Rectangle rect = calculateSignatureRectangle(
                    primaryPlacement,
                    canvasWidth,
                    canvasHeight,
                    pageSize.getWidth(),
                    pageSize.getHeight()
            );

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason("Signed Authorization")
                    .setLocation(location)
                    .setPageRect(rect)
                    .setPageNumber(primaryPlacement.pageNumber);

            if (signatureImageFile.exists() && signatureImageFile.length() > 0) {
                try {
                    ImageData imageData = ImageDataFactory.create(signatureImageFile.getAbsolutePath());
                    appearance.setSignatureGraphic(imageData);
                    appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
                    System.out.println("   ✅ Signature graphic set");
                } catch (Exception e) {
                    appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
                }
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            }

            IExternalSignature pks = new PrivateKeySignature(
                    privateKey,
                    DigestAlgorithms.SHA256,
                    BouncyCastleProvider.PROVIDER_NAME
            );
            IExternalDigest digest = new BouncyCastleDigest();

            ITSAClient tsaClient = getTsaClient();

            signer.signDetached(
                    digest,
                    pks,
                    chain,
                    null,
                    null,
                    tsaClient,
                    32768,
                    PdfSigner.CryptoStandard.CADES
            );

            System.out.println("   ✅ Digital signature applied");

        } finally {
            if (fos != null) fos.close();
            if (reader != null) reader.close();
        }
    }

    private ITSAClient getTsaClient() {
        if (tsaEnabled && tsaUrl != null && !tsaUrl.isEmpty()) {
            try {
                if (tsaUrl.contains("govca.npki.gov.ph")) {
                    return new TSAClientBouncyCastle(tsaUrl);
                } else if (tsaUsername != null && !tsaUsername.isEmpty()) {
                    return new TSAClientBouncyCastle(tsaUrl, tsaUsername, tsaPassword);
                } else {
                    return new TSAClientBouncyCastle(tsaUrl);
                }
            } catch (Exception e) {
                System.err.println("   ⚠️  TSA failed: " + e.getMessage());
            }
        }
        return null;
    }

    private String getFileExtension(String filename) {
        if (filename != null && filename.contains(".")) {
            return "." + filename.substring(filename.lastIndexOf(".") + 1);
        }
        return ".png";
    }

    private void loadPdf(File file) {
        try {
            if (currentDoc != null) currentDoc.close();
            currentDoc = PDDocument.load(file);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String signPdf(
            MultipartFile pdfDocument,
            MultipartFile signatureImage,
            MultipartFile certificateFile,
            int pageNumber,
            float x,
            float y,
            float width,
            float height,
            float canvasWidth,
            float canvasHeight,
            String password,
            String location) throws Exception {

        List<SignaturePlacement> placements = Arrays.asList(
                new SignaturePlacement(pageNumber, x, y, width, height)
        );

        return signPdfMultiPage(
                pdfDocument,
                signatureImage,
                certificateFile,
                placements,
                canvasWidth,
                canvasHeight,
                password,
                location
        );
    }

    public static List<SignaturePlacement> createPlacementsForPages(
            List<Integer> pageNumbers, float x, float y, float width, float height) {
        List<SignaturePlacement> placements = new ArrayList<>();
        for (Integer pageNum : pageNumbers) {
            placements.add(new SignaturePlacement(pageNum, x, y, width, height));
        }
        return placements;
    }

    public static List<SignaturePlacement> createPlacementsForRange(
            int startPage, int endPage, float x, float y, float width, float height) {
        List<SignaturePlacement> placements = new ArrayList<>();
        for (int i = startPage; i <= endPage; i++) {
            placements.add(new SignaturePlacement(i, x, y, width, height));
        }
        return placements;
    }

    public static List<SignaturePlacement> createPlacementsForAllPages(
            int totalPages, float x, float y, float width, float height) {
        return createPlacementsForRange(1, totalPages, x, y, width, height);
    }

    public Map<String, Object> verifySignatures(File pdfFile) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        PdfReader reader = new PdfReader(pdfFile.getAbsolutePath());
        PdfDocument pdfDoc = new PdfDocument(reader);

        SignatureUtil signatureUtil = new SignatureUtil(pdfDoc);
        List<String> signatureNames = signatureUtil.getSignatureNames();

        List<Map<String, Object>> signatureResults = new ArrayList<>();
        boolean allValid = true;

        for (String signatureName : signatureNames) {
            Map<String, Object> signatureInfo = new HashMap<>();
            signatureInfo.put("name", signatureName);

            try {
                PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(signatureName);

                boolean certValid = pkcs7.verifySignatureIntegrityAndAuthenticity();
                signatureInfo.put("certificateValid", certValid);

                boolean docValid = signatureUtil.signatureCoversWholeDocument(signatureName);
                signatureInfo.put("documentIntegrityValid", docValid);

                signatureInfo.put("signerName", pkcs7.getSignName());
                signatureInfo.put("signDate", pkcs7.getSignDate().getTime());
                signatureInfo.put("location", pkcs7.getLocation());
                signatureInfo.put("reason", pkcs7.getReason());

                try {
                    Calendar timestampDate = pkcs7.getTimeStampDate();
                    if (timestampDate != null) {
                        signatureInfo.put("hasTimestamp", true);
                        signatureInfo.put("timestampDate", timestampDate.getTime());
                    } else {
                        signatureInfo.put("hasTimestamp", false);
                    }
                } catch (Exception tsEx) {
                    signatureInfo.put("hasTimestamp", false);
                }

                boolean isValid = certValid && docValid;
                signatureInfo.put("valid", isValid);

                if (!isValid) allValid = false;

            } catch (Exception e) {
                signatureInfo.put("valid", false);
                signatureInfo.put("error", e.getMessage());
                allValid = false;
            }

            signatureResults.add(signatureInfo);
        }

        pdfDoc.close();

        Map<String, Object> result = new HashMap<>();
        result.put("signatureCount", signatureNames.size());
        result.put("allValid", allValid);
        result.put("signatures", signatureResults);

        return result;
    }

    public boolean hasSignatures(File pdfFile) throws Exception {
        PdfReader reader = new PdfReader(pdfFile.getAbsolutePath());
        PdfDocument pdfDoc = new PdfDocument(reader);

        SignatureUtil signatureUtil = new SignatureUtil(pdfDoc);
        List<String> signatureNames = signatureUtil.getSignatureNames();

        boolean hasSignatures = !signatureNames.isEmpty();
        pdfDoc.close();

        return hasSignatures;
    }
}