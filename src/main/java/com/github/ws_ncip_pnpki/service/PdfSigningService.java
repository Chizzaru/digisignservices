package com.github.ws_ncip_pnpki.service;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Canvas;
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
public class PdfSigningService {
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

        // Validate certificate before proceeding
        validateCertificate(chain);

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
                    chain,
                    location,
                    "Signed Authorization"
            );

            System.out.println("\n=== STEP 2: Applying Digital Signature ===");
            signPdfWithDigitalSignatureEnhanced(
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

    /**
     * Validate certificate before signing
     */
    private void validateCertificate(Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Certificate chain is empty");
        }

        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) chain[0];

        System.out.println("\n=== Certificate Validation ===");
        System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
        System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("Serial: " + cert.getSerialNumber());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid Until: " + cert.getNotAfter());
        System.out.println("Chain Length: " + chain.length);

        // Check if certificate is currently valid
        try {
            cert.checkValidity();
            System.out.println("✅ Certificate is currently valid");
        } catch (Exception e) {
            System.err.println("❌ Certificate validity check failed: " + e.getMessage());
            throw new Exception("Certificate is not valid: " + e.getMessage());
        }

        // Check if self-signed
        boolean isSelfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
        if (isSelfSigned) {
            System.out.println("⚠️  Certificate is self-signed");
        }

        // Verify certificate chain
        for (int i = 0; i < chain.length; i++) {
            java.security.cert.X509Certificate c = (java.security.cert.X509Certificate) chain[i];
            System.out.println("  Chain[" + i + "]: " + c.getSubjectX500Principal().getName());
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
        System.out.println("   Digital signature page: " + digitalSignaturePage + " (will also get visual signature)");

        PdfReader reader = new PdfReader(srcPdf);
        PdfWriter writer = new PdfWriter(destPdf);
        PdfDocument pdfDoc = new PdfDocument(reader, writer);

        try {
            if (!signatureImageFile.exists()) {
                throw new Exception("Signature file not found");
            }

            ImageData imageData = ImageDataFactory.create(signatureImageFile.getAbsolutePath());
            System.out.println("   Image loaded: " + imageData.getWidth() + "x" + imageData.getHeight() + " pixels");

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

                System.out.println("\n📝 Adding visual signature to Page " + placement.pageNumber);

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

                // Convert pixels to points (assuming 72 DPI for PDF)
                float pointsPerPixel = 72f / 96f;
                float originalWidth = imageData.getWidth() * pointsPerPixel * 1.5f;
                float originalHeight = imageData.getHeight() * pointsPerPixel * 1.5f;

                System.out.println("   Original image size: " + imageData.getWidth() + "x" + imageData.getHeight() + " pixels");
                System.out.println("   Converted to PDF: " + originalWidth + "x" + originalHeight + " points");

                // Check if image fits in the rectangle
                float scale = 1.0f;
                float maxImageHeight = rect.getHeight() * 0.7f;

                if (originalWidth > rect.getWidth() || originalHeight > maxImageHeight) {
                    float widthScale = rect.getWidth() / originalWidth;
                    float heightScale = maxImageHeight / originalHeight;
                    scale = Math.min(widthScale, heightScale);
                    System.out.println("   Scaling image by: " + scale + " to fit");
                }

                float imageWidth = originalWidth * scale;
                float imageHeight = originalHeight * scale;

                System.out.println("   Final image size: " + imageWidth + "x" + imageHeight + " points");

                // Calculate centered position for image
                float imageX = rect.getX() + (rect.getWidth() - imageWidth) / 2;
                float imageY = rect.getY() + rect.getHeight() - imageHeight - 4;

                // Add image
                pdfCanvas.saveState();
                pdfCanvas.concatMatrix(scale, 0, 0, scale, imageX, imageY);
                pdfCanvas.addImageAt(imageData, 0, 0, false);
                pdfCanvas.restoreState();

                // Add text
                com.itextpdf.kernel.font.PdfFont font = com.itextpdf.kernel.font.PdfFontFactory.createFont();
                com.itextpdf.kernel.font.PdfFont boldFont = com.itextpdf.kernel.font.PdfFontFactory.createFont(
                        com.itextpdf.io.font.constants.StandardFonts.HELVETICA_BOLD
                );

                float textAreaTop = imageY - 8;
                float textY = textAreaTop;

                // Signer name (bold, centered)
                float nameWidth = boldFont.getWidth(signerName, 10);
                float textX = rect.getX() + (rect.getWidth() - nameWidth) / 2;

                pdfCanvas.saveState();
                pdfCanvas.beginText();
                pdfCanvas.setFontAndSize(boldFont, 10);
                pdfCanvas.moveText(textX, textY);
                pdfCanvas.showText(signerName);
                pdfCanvas.endText();
                pdfCanvas.restoreState();
                textY -= 14;

                // Reason (centered)
                if (reason != null && !reason.isEmpty()) {
                    String reasonText = "Reason: " + reason;
                    float reasonWidth = font.getWidth(reasonText, 8);
                    float reasonX = rect.getX() + (rect.getWidth() - reasonWidth) / 2;

                    pdfCanvas.saveState();
                    pdfCanvas.beginText();
                    pdfCanvas.setFontAndSize(font, 8);
                    pdfCanvas.moveText(reasonX, textY);
                    pdfCanvas.showText(reasonText);
                    pdfCanvas.endText();
                    pdfCanvas.restoreState();
                    textY -= 10;
                }

                // Location (centered)
                if (location != null && !location.isEmpty()) {
                    String locationText = "Location: " + location;
                    float locationWidth = font.getWidth(locationText, 8);
                    float locationX = rect.getX() + (rect.getWidth() - locationWidth) / 2;

                    pdfCanvas.saveState();
                    pdfCanvas.beginText();
                    pdfCanvas.setFontAndSize(font, 8);
                    pdfCanvas.moveText(locationX, textY);
                    pdfCanvas.showText(locationText);
                    pdfCanvas.endText();
                    pdfCanvas.restoreState();
                    textY -= 10;
                }

                // Date (centered)
                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String dateStr = sdf.format(new java.util.Date());
                String dateText = "Date: " + dateStr;
                float dateWidth = font.getWidth(dateText, 8);
                float dateX = rect.getX() + (rect.getWidth() - dateWidth) / 2;

                pdfCanvas.saveState();
                pdfCanvas.beginText();
                pdfCanvas.setFontAndSize(font, 8);
                pdfCanvas.moveText(dateX, textY);
                pdfCanvas.showText(dateText);
                pdfCanvas.endText();
                pdfCanvas.restoreState();

                added++;
                System.out.println("   ✅ Added visual signature");
            }

            System.out.println("\n✅ Visual signatures added: " + added);

        } finally {
            pdfDoc.close();
        }
    }

    /**
     * Enhanced signing method with certificate validation
     */
    private void signPdfWithDigitalSignatureEnhanced(
            File srcPdf,
            File destPdf,
            PrivateKey privateKey,
            Certificate[] chain,
            List<SignaturePlacement> placements,
            float canvasWidth,
            float canvasHeight,
            String location,
            File signatureImageFile) throws Exception {

        System.out.println("🔐 Applying digital signature with enhanced validation");

        StampingProperties stampingProperties = new StampingProperties();
        stampingProperties.useAppendMode();

        PdfReader reader = new PdfReader(srcPdf);
        FileOutputStream fos = new FileOutputStream(destPdf);

        try {
            PdfSigner signer = new PdfSigner(reader, fos, stampingProperties);

            String fieldName = "Signature_" + UUID.randomUUID().toString().substring(0, 8);
            signer.setFieldName(fieldName);

            SignaturePlacement primaryPlacement = placements.get(0);

            // Create invisible signature (1x1 pixel)
            Rectangle rect = new Rectangle(0, 0, 1, 1);

            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance
                    .setReason("Signed Authorization")
                    .setLocation(location)
                    .setPageRect(rect)
                    .setPageNumber(primaryPlacement.pageNumber)
                    .setCertificate(chain[0]);

            System.out.println("   ✅ Digital signature configured on page " + primaryPlacement.pageNumber);

            // Use RSA with SHA-256 for better compatibility
            IExternalSignature pks = new PrivateKeySignature(
                    privateKey,
                    DigestAlgorithms.SHA256,
                    BouncyCastleProvider.PROVIDER_NAME
            );
            IExternalDigest digest = new BouncyCastleDigest();

            // Get TSA client (can be null)
            ITSAClient tsaClient = getTsaClient();

            // Sign with full certificate chain
            // Use CryptoStandard.CMS instead of CADES for better compatibility
            signer.signDetached(
                    digest,
                    pks,
                    chain,
                    null,  // CRL clients
                    null,  // OCSP client
                    tsaClient,
                    32768,     // Estimated size (0 = auto)
                    PdfSigner.CryptoStandard.CMS
            );

            System.out.println("   ✅ Digital signature applied successfully");

        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
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

    /**
     * Enhanced verification with detailed certificate checks
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

        System.out.println("\n=== Verifying Signatures ===");
        System.out.println("Found " + signatureNames.size() + " signature(s)");

        for (String signatureName : signatureNames) {
            System.out.println("\n--- Verifying: " + signatureName + " ---");
            Map<String, Object> signatureInfo = new HashMap<>();
            signatureInfo.put("name", signatureName);

            try {
                PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(signatureName);

                // 1. Check signature integrity (cryptographic validity)
                boolean signatureIntegrity = pkcs7.verifySignatureIntegrityAndAuthenticity();
                signatureInfo.put("signatureIntegrity", signatureIntegrity);
                signatureInfo.put("certificateValid", signatureIntegrity); // Added for compatibility
                System.out.println("Signature Integrity: " + (signatureIntegrity ? "✅ VALID" : "❌ INVALID"));

                // 2. Check if document was modified after signing
                boolean documentIntegrity = signatureUtil.signatureCoversWholeDocument(signatureName);
                signatureInfo.put("documentIntegrity", documentIntegrity);
                signatureInfo.put("documentIntegrityValid", documentIntegrity); // Added for compatibility
                System.out.println("Document Integrity: " + (documentIntegrity ? "✅ VALID" : "❌ INVALID"));

                // 3. Get certificate information
                java.security.cert.X509Certificate signerCert = pkcs7.getSigningCertificate();
                String subjectDN = signerCert.getSubjectX500Principal().getName();
                String issuerDN = signerCert.getIssuerX500Principal().getName();

                signatureInfo.put("signerName", extractCN(subjectDN));
                signatureInfo.put("subjectDN", subjectDN);
                signatureInfo.put("issuerDN", issuerDN);
                signatureInfo.put("serialNumber", signerCert.getSerialNumber().toString());

                System.out.println("Signer: " + extractCN(subjectDN));
                System.out.println("Issuer: " + extractCN(issuerDN));

                // 4. Check certificate validity period
                Date signDate = pkcs7.getSignDate().getTime();
                signatureInfo.put("signDate", signDate);

                boolean certValidAtSigningTime = true;
                String certValidityMessage = "";
                try {
                    signerCert.checkValidity(signDate);
                    certValidityMessage = "✅ Certificate was valid at signing time";
                    System.out.println(certValidityMessage);
                } catch (java.security.cert.CertificateExpiredException e) {
                    certValidAtSigningTime = false;
                    certValidityMessage = "❌ Certificate was expired at signing time";
                    System.out.println(certValidityMessage);
                } catch (java.security.cert.CertificateNotYetValidException e) {
                    certValidAtSigningTime = false;
                    certValidityMessage = "❌ Certificate was not yet valid at signing time";
                    System.out.println(certValidityMessage);
                }
                signatureInfo.put("certificateValidAtSigningTime", certValidAtSigningTime);
                signatureInfo.put("certificateValidityMessage", certValidityMessage);

                // 5. Check if self-signed
                boolean isSelfSigned = issuerDN.equals(subjectDN);
                signatureInfo.put("isSelfSigned", isSelfSigned);
                if (isSelfSigned) {
                    System.out.println("⚠️  Self-signed certificate");
                }

                // 6. Get certificate chain
                Certificate[] certs = pkcs7.getCertificates();
                signatureInfo.put("certificateChainLength", certs.length);
                System.out.println("Certificate Chain Length: " + certs.length);

                // 7. Check for timestamp
                boolean hasTimestamp = false;
                try {
                    Calendar timestampDate = pkcs7.getTimeStampDate();
                    if (timestampDate != null) {
                        hasTimestamp = true;
                        signatureInfo.put("timestampDate", timestampDate.getTime());
                        System.out.println("✅ Has timestamp: " + timestampDate.getTime());
                    } else {
                        System.out.println("⚠️  No timestamp");
                    }
                } catch (Exception tsEx) {
                    System.out.println("⚠️  No timestamp");
                }
                signatureInfo.put("hasTimestamp", hasTimestamp);

                // 8. Additional metadata
                signatureInfo.put("location", pkcs7.getLocation());
                signatureInfo.put("reason", pkcs7.getReason());

                // 9. Overall validity determination
                boolean isValid = signatureIntegrity && documentIntegrity && certValidAtSigningTime;

                signatureInfo.put("valid", isValid);
                signatureInfo.put("trustStatus", isSelfSigned ?
                        "Self-signed (requires manual trust)" :
                        "Issued by CA");

                System.out.println("\n=== Overall Status: " + (isValid ? "✅ VALID" : "❌ INVALID") + " ===");

                if (!isValid) {
                    List<String> issues = new ArrayList<>();
                    if (!signatureIntegrity) issues.add("Signature integrity check failed");
                    if (!documentIntegrity) issues.add("Document was modified after signing");
                    if (!certValidAtSigningTime) issues.add("Certificate not valid at signing time");
                    signatureInfo.put("issues", issues);
                    System.out.println("Issues: " + String.join(", ", issues));
                    allValid = false;
                }

            } catch (Exception e) {
                signatureInfo.put("valid", false);
                signatureInfo.put("error", e.getMessage());
                System.err.println("❌ Verification error: " + e.getMessage());
                e.printStackTrace();
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

    /**
     * Extract Common Name from Distinguished Name
     */
    private String extractCN(String dn) {
        if (dn == null) return "Unknown";
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }

    /**
     * Analyze certificate file for debugging
     */
    public Map<String, Object> analyzeCertificateFile(MultipartFile certFile, String password) {
        Map<String, Object> info = new HashMap<>();
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(certFile.getInputStream(), password.toCharArray());

            String alias = ks.aliases().nextElement();
            Certificate[] chain = ks.getCertificateChain(alias);

            info.put("alias", alias);
            info.put("chainLength", chain.length);

            List<Map<String, Object>> certs = new ArrayList<>();
            for (int i = 0; i < chain.length; i++) {
                java.security.cert.X509Certificate cert =
                        (java.security.cert.X509Certificate) chain[i];

                Map<String, Object> certInfo = new HashMap<>();
                certInfo.put("index", i);
                certInfo.put("subject", cert.getSubjectX500Principal().getName());
                certInfo.put("issuer", cert.getIssuerX500Principal().getName());
                certInfo.put("notBefore", cert.getNotBefore());
                certInfo.put("notAfter", cert.getNotAfter());
                certInfo.put("serialNumber", cert.getSerialNumber().toString());

                // Check current validity
                try {
                    cert.checkValidity();
                    certInfo.put("currentlyValid", true);
                } catch (Exception e) {
                    certInfo.put("currentlyValid", false);
                    certInfo.put("validityError", e.getMessage());
                }

                certs.add(certInfo);
            }

            info.put("certificates", certs);
            info.put("success", true);

        } catch (Exception e) {
            info.put("success", false);
            info.put("error", e.getMessage());
        }

        return info;
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