package com.github.ws_ncip_pnpki.service;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.element.Image;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.properties.TextAlignment;
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
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class PdfSigningService_Working {
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

    /**
     * Data class to hold signature placement information for each page
     */
    public static class SignaturePlacement {
        public int pageNumber;
        public float x;
        public float y;
        public float width;
        public float height;

        public SignaturePlacement() {
        }

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

    /**
     * Sign PDF with signature image appearing on multiple pages
     * First adds visual signature images to all specified pages, then applies digital signature
     */
    public String signPdfMultiPage(
            MultipartFile pdfDocument,
            MultipartFile signatureImage,
            MultipartFile certificateFile,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String password) throws Exception {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        // Extract certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream certInputStream = certificateFile.getInputStream()) {
            keyStore.load(certInputStream, password.toCharArray());
        }

        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);

        // Save uploaded files to temporary locations
        File tempPdfFile = File.createTempFile("temp_pdf_", ".pdf");
        File tempSignatureFile = File.createTempFile("temp_sig_", getFileExtension(signatureImage.getOriginalFilename()));
        File tempStampedPdf = File.createTempFile("temp_stamped_", ".pdf");

        pdfDocument.transferTo(tempPdfFile);
        signatureImage.transferTo(tempSignatureFile);

        // Load PDF with PDFBox for page dimension reading
        loadPdf(tempPdfFile);

        if (!tempSignatureFile.exists() || tempSignatureFile.length() == 0) {
            throw new Exception("Signature image file is empty or not created");
        }

        // Generate output file name
        String outputFileName = "signed_" + UUID.randomUUID() + ".pdf";
        File outputFile = new File(outputDir, outputFileName);

        try {
            // Step 1: Add visual signature images to multiple pages
            System.out.println("\n=== STEP 1: Adding Visual Signatures ===");
            addVisualSignaturesToPages(
                    tempPdfFile,
                    tempStampedPdf,
                    placements,
                    canvasWidth,
                    canvasHeight,
                    tempSignatureFile
            );

            // Step 2: Apply digital signature to the stamped PDF
            System.out.println("\n=== STEP 2: Applying Digital Signature ===");
            signPdfWithDigitalSignature(
                    tempStampedPdf,
                    outputFile,
                    privateKey,
                    chain,
                    placements, // Pass all placements for proper multi-page signature field
                    canvasWidth,
                    canvasHeight
            );

            System.out.println("\n✅ Multi-page signing completed successfully!");
            System.out.println("   Total pages signed: " + placements.size());
            System.out.println("   Output file: " + outputFileName);

            return outputFileName;

        } finally {
            // Clean up temporary files
            if (tempPdfFile.exists()) tempPdfFile.delete();
            if (tempSignatureFile.exists()) tempSignatureFile.delete();
            if (tempStampedPdf.exists()) tempStampedPdf.delete();
            if (currentDoc != null) currentDoc.close();
        }
    }

    /**
     * Original single-page signing method (backward compatibility)
     */
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
            String password) throws Exception {

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
                password
        );
    }

    /**
     * Helper methods for creating placements
     */
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

    /**
     * Step 1: Add visual signature images to multiple pages WITHOUT digital signature
     * This stamps the signature image and text on each specified page
     */
    private void addVisualSignaturesToPages(
            File srcPdf,
            File destPdf,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            File signatureImageFile) throws Exception {

        System.out.println("📄 Adding visual signatures to " + placements.size() + " page(s)");

        PdfReader reader = new PdfReader(srcPdf);
        PdfWriter writer = new PdfWriter(destPdf);
        PdfDocument pdfDoc = new PdfDocument(reader, writer);

        // Get current timestamp
        ZonedDateTime signTime = ZonedDateTime.now(ZoneId.of("Asia/Manila"));
        String formattedTime = signTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z"));

        try {
            for (SignaturePlacement placement : placements) {
                int pageNum = placement.pageNumber;

                if (pageNum < 1 || pageNum > pdfDoc.getNumberOfPages()) {
                    System.err.println("⚠️  Skipping invalid page number: " + pageNum);
                    continue;
                }

                System.out.println("\n📍 Processing Page " + pageNum);

                // Get page dimensions from PDFBox
                org.apache.pdfbox.pdmodel.PDPage pdPage = currentDoc.getPage(pageNum - 1);
                org.apache.pdfbox.pdmodel.common.PDRectangle mediaBox = pdPage.getMediaBox();
                float pdfPageWidth = mediaBox.getWidth();
                float pdfPageHeight = mediaBox.getHeight();

                System.out.println("   PDF Page Size: " + pdfPageWidth + " x " + pdfPageHeight + " pts");
                System.out.println("   Canvas Size: " + canvasWidth + " x " + canvasHeight + " pts");

                // Calculate scale factors
                float scaleX = pdfPageWidth / canvasWidth;
                float scaleY = pdfPageHeight / canvasHeight;

                System.out.println("   Scale Factors: X=" + scaleX + ", Y=" + scaleY);

                // Convert canvas coordinates to PDF coordinates
                float pdfX = placement.x * scaleX;
                float pdfWidth = placement.width * scaleX;
                float pdfHeight = placement.height * scaleY;
                // Flip Y coordinate (canvas Y=0 is top, PDF Y=0 is bottom)
                float pdfY = pdfPageHeight - ((placement.y + placement.height) * scaleY);

                System.out.println("   Canvas Position: X=" + placement.x + ", Y=" + placement.y +
                        ", W=" + placement.width + ", H=" + placement.height);
                System.out.println("   PDF Position: X=" + pdfX + ", Y=" + pdfY +
                        ", W=" + pdfWidth + ", H=" + pdfHeight);

                // Bounds checking
                pdfX = Math.max(0, Math.min(pdfX, pdfPageWidth - pdfWidth));
                pdfY = Math.max(0, Math.min(pdfY, pdfPageHeight - pdfHeight));
                pdfWidth = Math.min(pdfWidth, pdfPageWidth - pdfX);
                pdfHeight = Math.min(pdfHeight, pdfPageHeight - pdfY);

                // Get the page and create canvas for drawing
                com.itextpdf.kernel.pdf.PdfPage page = pdfDoc.getPage(pageNum);
                PdfCanvas pdfCanvas = new PdfCanvas(page.newContentStreamAfter(),
                        page.getResources(),
                        pdfDoc);

                // Create layout canvas for adding content
                Rectangle rect = new Rectangle(pdfX, pdfY, pdfWidth, pdfHeight);
                Canvas layoutCanvas = new Canvas(pdfCanvas, rect);

                // Add signature image
                if (signatureImageFile.exists() && signatureImageFile.length() > 0) {
                    try {
                        Image img = new Image(ImageDataFactory.create(signatureImageFile.getAbsolutePath()));

                        // Scale image to fit within signature box
                        float imgWidth = pdfWidth * 0.9f;  // 90% of box width
                        float imgHeight = pdfHeight * 0.6f; // 60% of box height for image

                        img.setWidth(imgWidth);
                        img.setHeight(imgHeight);
                        img.setHorizontalAlignment(com.itextpdf.layout.properties.HorizontalAlignment.CENTER);

                        layoutCanvas.add(img);
                        System.out.println("   ✅ Signature image added");
                    } catch (Exception e) {
                        System.err.println("   ❌ Failed to add image: " + e.getMessage());
                    }
                }

                // Add text below image
                Paragraph signText = new Paragraph("Digitally Signed\n" + formattedTime)
                        .setFontSize(7)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setMarginTop(5);

                layoutCanvas.add(signText);
                layoutCanvas.close();

                System.out.println("   ✅ Visual signature added to page " + pageNum);
            }

            System.out.println("\n✅ All visual signatures stamped successfully");

        } finally {
            pdfDoc.close();
        }
    }

    /**
     * Step 2: Apply digital signature to the PDF that already has visual stamps
     * This creates one cryptographic signature that validates the entire document
     * Now supports multiple signature field placements
     */
    private void signPdfWithDigitalSignature(
            File srcPdf,
            File destPdf,
            PrivateKey privateKey,
            Certificate[] chain,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight) throws Exception {

        System.out.println("🔐 Applying digital signature to document");

        // Use append mode to preserve existing content
        StampingProperties stampingProperties = new StampingProperties();
        stampingProperties.useAppendMode();

        PdfReader reader = new PdfReader(srcPdf);
        FileOutputStream fos = new FileOutputStream(destPdf);

        try {
            PdfSigner signer = new PdfSigner(reader, fos, stampingProperties);

            // Create unique signature field name
            String fieldName = "Signature_" + UUID.randomUUID().toString().substring(0, 8);
            signer.setFieldName(fieldName);

            System.out.println("   Signature field: " + fieldName);

            // Use the first placement for the primary signature field location
            SignaturePlacement primaryPlacement = placements.get(0);

            // Get page dimensions for signature field placement
            org.apache.pdfbox.pdmodel.PDPage pdPage = currentDoc.getPage(primaryPlacement.pageNumber - 1);
            org.apache.pdfbox.pdmodel.common.PDRectangle mediaBox = pdPage.getMediaBox();
            float pdfPageWidth = mediaBox.getWidth();
            float pdfPageHeight = mediaBox.getHeight();

            float scaleX = pdfPageWidth / canvasWidth;
            float scaleY = pdfPageHeight / canvasHeight;

            float pdfX = primaryPlacement.x * scaleX;
            float pdfWidth = primaryPlacement.width * scaleX;
            float pdfHeight = primaryPlacement.height * scaleY;
            float pdfY = pdfPageHeight - ((primaryPlacement.y + primaryPlacement.height) * scaleY);

            // Bounds checking
            pdfX = Math.max(0, Math.min(pdfX, pdfPageWidth - pdfWidth));
            pdfY = Math.max(0, Math.min(pdfY, pdfPageHeight - pdfHeight));

            Rectangle rect = new Rectangle(pdfX, pdfY, pdfWidth, pdfHeight);

            // Configure signature appearance
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason("Signed Authorization")
                    .setLocation("Quezon City, Philippines")
                    .setPageRect(rect)
                    .setPageNumber(primaryPlacement.pageNumber)
                    .setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);

            System.out.println("   Primary signature location: Page " + primaryPlacement.pageNumber);
            System.out.println("   Total signature placements: " + placements.size());

            // Setup cryptographic signature
            IExternalSignature pks = new PrivateKeySignature(
                    privateKey,
                    DigestAlgorithms.SHA256,
                    BouncyCastleProvider.PROVIDER_NAME
            );
            IExternalDigest digest = new BouncyCastleDigest();

            // Configure TSA Client if enabled
            ITSAClient tsaClient = null;
            if (tsaEnabled && tsaUrl != null && !tsaUrl.isEmpty()) {
                try {
                    System.out.println("\n⏳ Connecting to TSA: " + tsaUrl);

                    if (tsaUrl.contains("govca.npki.gov.ph")) {
                        System.out.println("   🇵🇭 Using DICT TSA configuration");
                        tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    } else if (tsaUsername != null && !tsaUsername.isEmpty()) {
                        tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUsername, tsaPassword);
                        System.out.println("   ✅ TSA with authentication configured");
                    } else {
                        tsaClient = new TSAClientBouncyCastle(tsaUrl);
                        System.out.println("   ✅ TSA configured (no auth)");
                    }
                } catch (Exception e) {
                    System.err.println("   ❌ TSA connection failed: " + e.getMessage());
                    System.err.println("   ⚠️  Continuing without timestamp");
                    tsaClient = null;
                }
            } else {
                System.out.println("   ⚠️  TSA disabled - signing without timestamp");
            }

            // Perform the digital signature
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

            if (tsaClient != null) {
                System.out.println("   ✅ Digital signature applied WITH timestamp");
            } else {
                System.out.println("   ✅ Digital signature applied (no timestamp)");
            }

        } finally {
            if (fos != null) fos.close();
            if (reader != null) reader.close();
        }
    }

    /**
     * Alternative method for signing with custom signature appearance on multiple pages
     */
    public String signPdfMultiPageWithCustomAppearance(
            MultipartFile pdfDocument,
            MultipartFile signatureImage,
            MultipartFile certificateFile,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String password,
            String reason,
            String location) throws Exception {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        // Extract certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream certInputStream = certificateFile.getInputStream()) {
            keyStore.load(certInputStream, password.toCharArray());
        }

        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        Certificate[] chain = keyStore.getCertificateChain(alias);

        // Save uploaded files to temporary locations
        File tempPdfFile = File.createTempFile("temp_pdf_", ".pdf");
        File tempSignatureFile = File.createTempFile("temp_sig_", getFileExtension(signatureImage.getOriginalFilename()));
        File tempStampedPdf = File.createTempFile("temp_stamped_", ".pdf");

        pdfDocument.transferTo(tempPdfFile);
        signatureImage.transferTo(tempSignatureFile);

        // Load PDF with PDFBox for page dimension reading
        loadPdf(tempPdfFile);

        // Generate output file name
        String outputFileName = "signed_" + UUID.randomUUID() + ".pdf";
        File outputFile = new File(outputDir, outputFileName);

        try {
            // Step 1: Add visual signature images to multiple pages
            System.out.println("\n=== STEP 1: Adding Visual Signatures ===");
            addVisualSignaturesToPages(
                    tempPdfFile,
                    tempStampedPdf,
                    placements,
                    canvasWidth,
                    canvasHeight,
                    tempSignatureFile
            );

            // Step 2: Apply digital signature with custom appearance
            System.out.println("\n=== STEP 2: Applying Digital Signature with Custom Appearance ===");
            signPdfWithDigitalSignatureCustom(
                    tempStampedPdf,
                    outputFile,
                    privateKey,
                    chain,
                    placements,
                    canvasWidth,
                    canvasHeight,
                    reason,
                    location
            );

            System.out.println("\n✅ Multi-page signing with custom appearance completed successfully!");
            System.out.println("   Total pages signed: " + placements.size());
            System.out.println("   Output file: " + outputFileName);

            return outputFileName;

        } finally {
            // Clean up temporary files
            if (tempPdfFile.exists()) tempPdfFile.delete();
            if (tempSignatureFile.exists()) tempSignatureFile.delete();
            if (tempStampedPdf.exists()) tempStampedPdf.delete();
            if (currentDoc != null) currentDoc.close();
        }
    }

    /**
     * Enhanced digital signature method with custom appearance support
     */
    private void signPdfWithDigitalSignatureCustom(
            File srcPdf,
            File destPdf,
            PrivateKey privateKey,
            Certificate[] chain,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String reason,
            String location) throws Exception {

        System.out.println("🔐 Applying digital signature with custom appearance");

        // Use append mode to preserve existing content
        StampingProperties stampingProperties = new StampingProperties();
        stampingProperties.useAppendMode();

        PdfReader reader = new PdfReader(srcPdf);
        FileOutputStream fos = new FileOutputStream(destPdf);

        try {
            PdfSigner signer = new PdfSigner(reader, fos, stampingProperties);

            // Create unique signature field name
            String fieldName = "Signature_" + UUID.randomUUID().toString().substring(0, 8);
            signer.setFieldName(fieldName);

            System.out.println("   Signature field: " + fieldName);
            System.out.println("   Reason: " + reason);
            System.out.println("   Location: " + location);

            // Use the first placement for the primary signature field location
            SignaturePlacement primaryPlacement = placements.get(0);

            // Get page dimensions for signature field placement
            org.apache.pdfbox.pdmodel.PDPage pdPage = currentDoc.getPage(primaryPlacement.pageNumber - 1);
            org.apache.pdfbox.pdmodel.common.PDRectangle mediaBox = pdPage.getMediaBox();
            float pdfPageWidth = mediaBox.getWidth();
            float pdfPageHeight = mediaBox.getHeight();

            float scaleX = pdfPageWidth / canvasWidth;
            float scaleY = pdfPageHeight / canvasHeight;

            float pdfX = primaryPlacement.x * scaleX;
            float pdfWidth = primaryPlacement.width * scaleX;
            float pdfHeight = primaryPlacement.height * scaleY;
            float pdfY = pdfPageHeight - ((primaryPlacement.y + primaryPlacement.height) * scaleY);

            // Bounds checking
            pdfX = Math.max(0, Math.min(pdfX, pdfPageWidth - pdfWidth));
            pdfY = Math.max(0, Math.min(pdfY, pdfPageHeight - pdfHeight));

            Rectangle rect = new Rectangle(pdfX, pdfY, pdfWidth, pdfHeight);

            // Configure signature appearance with custom settings
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason(reason)
                    .setLocation(location)
                    .setPageRect(rect)
                    .setPageNumber(primaryPlacement.pageNumber)
                    .setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);

            System.out.println("   Primary signature location: Page " + primaryPlacement.pageNumber);
            System.out.println("   Total signature placements: " + placements.size());

            // Setup cryptographic signature
            IExternalSignature pks = new PrivateKeySignature(
                    privateKey,
                    DigestAlgorithms.SHA256,
                    BouncyCastleProvider.PROVIDER_NAME
            );
            IExternalDigest digest = new BouncyCastleDigest();

            // Configure TSA Client if enabled
            ITSAClient tsaClient = getTsaClient();

            // Perform the digital signature
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

            if (tsaClient != null) {
                System.out.println("   ✅ Digital signature applied WITH timestamp");
            } else {
                System.out.println("   ✅ Digital signature applied (no timestamp)");
            }

        } finally {
            if (fos != null) fos.close();
            if (reader != null) reader.close();
        }
    }

    /**
     * Helper method to get TSA client configuration
     */
    private ITSAClient getTsaClient() {
        if (tsaEnabled && tsaUrl != null && !tsaUrl.isEmpty()) {
            try {
                System.out.println("\n⏳ Connecting to TSA: " + tsaUrl);

                if (tsaUrl.contains("govca.npki.gov.ph")) {
                    System.out.println("   🇵🇭 Using DICT TSA configuration");
                    return new TSAClientBouncyCastle(tsaUrl);
                } else if (tsaUsername != null && !tsaUsername.isEmpty()) {
                    TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUsername, tsaPassword);
                    System.out.println("   ✅ TSA with authentication configured");
                    return tsaClient;
                } else {
                    TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    System.out.println("   ✅ TSA configured (no auth)");
                    return tsaClient;
                }
            } catch (Exception e) {
                System.err.println("   ❌ TSA connection failed: " + e.getMessage());
                System.err.println("   ⚠️  Continuing without timestamp");
            }
        } else {
            System.out.println("   ⚠️  TSA disabled - signing without timestamp");
        }
        return null;
    }

    /**
     * Verify all signatures in a PDF document
     */
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
}