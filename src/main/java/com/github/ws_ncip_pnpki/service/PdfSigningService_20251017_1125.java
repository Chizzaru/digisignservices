package com.github.ws_ncip_pnpki.service;

import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
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
public class PdfSigningService_20251017_1125 {
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

        // Register BouncyCastle provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Create output directory if not exists
        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        // Extract certificate and private key from .p12 file
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
        pdfDocument.transferTo(tempPdfFile);
        signatureImage.transferTo(tempSignatureFile);

        // Loading PDF
        loadPdf(tempPdfFile);

        // Verify signature image exists
        if (!tempSignatureFile.exists() || tempSignatureFile.length() == 0) {
            throw new Exception("Signature image file is empty or not created");
        }

        // Generate output file name
        String outputFileName = "signed_" + UUID.randomUUID() + ".pdf";
        File outputFile = new File(outputDir, outputFileName);

        try {
            // Sign the PDF with timestamp
            signPdfVisible(
                    tempPdfFile,
                    outputFile,
                    privateKey,
                    chain,
                    pageNumber,
                    x,
                    y,
                    width,
                    height,
                    canvasWidth,
                    canvasHeight,
                    tempSignatureFile
            );

            return outputFileName;

        } finally {
            // Clean up temporary files
            if (tempPdfFile.exists()) {
                tempPdfFile.delete();
            }
            if (tempSignatureFile.exists()) {
                tempSignatureFile.delete();
            }
            if (currentDoc != null) {
                currentDoc.close();
            }
        }
    }

    /**
     * Verify all signatures in a PDF document
     */
    public Map<String, Object> verifySignatures(File pdfFile) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        PdfReader reader = new PdfReader(pdfFile.getAbsolutePath());
        com.itextpdf.kernel.pdf.PdfDocument pdfDoc = new com.itextpdf.kernel.pdf.PdfDocument(reader);

        SignatureUtil signatureUtil = new SignatureUtil(pdfDoc);
        List<String> signatureNames = signatureUtil.getSignatureNames();

        List<Map<String, Object>> signatureResults = new ArrayList<>();
        boolean allValid = true;

        for (String signatureName : signatureNames) {
            Map<String, Object> signatureInfo = new HashMap<>();
            signatureInfo.put("name", signatureName);

            try {
                PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(signatureName);

                // Check certificate validity
                boolean certValid = pkcs7.verifySignatureIntegrityAndAuthenticity();
                signatureInfo.put("certificateValid", certValid);

                // Check document integrity
                boolean docValid = signatureUtil.signatureCoversWholeDocument(signatureName);
                signatureInfo.put("documentIntegrityValid", docValid);

                // Get signer info
                signatureInfo.put("signerName", pkcs7.getSignName());
                signatureInfo.put("signDate", pkcs7.getSignDate().getTime());
                signatureInfo.put("location", pkcs7.getLocation());
                signatureInfo.put("reason", pkcs7.getReason());

                // Check timestamp
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

                // Overall validity
                boolean isValid = certValid && docValid;
                signatureInfo.put("valid", isValid);

                if (!isValid) {
                    allValid = false;
                }

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

    /**
     * Check if a PDF has existing signatures
     */
    public boolean hasSignatures(File pdfFile) throws Exception {
        PdfReader reader = new PdfReader(pdfFile.getAbsolutePath());
        com.itextpdf.kernel.pdf.PdfDocument pdfDoc = new com.itextpdf.kernel.pdf.PdfDocument(reader);

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

    private void signPdfVisible(
            File src,
            File dest,
            PrivateKey pk,
            Certificate[] chain,
            int pageNumber,
            float x,
            float y,
            float width,
            float height,
            float canvasWidth,
            float canvasHeight,
            File signatureImageFile) throws Exception {

        // Ensure BouncyCastle provider registered
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Prepare stamping properties for append mode (allows multiple signatures)
        StampingProperties stampingProperties = new StampingProperties();
        stampingProperties.useAppendMode();

        PdfReader reader = new PdfReader(src.getAbsolutePath());

        try (FileOutputStream fos = new FileOutputStream(dest)) {

            PdfSigner signer = new PdfSigner(reader, fos, stampingProperties);
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();

            // Get page dimensions from PDDocument
            org.apache.pdfbox.pdmodel.PDPage pdPage = currentDoc.getPage(pageNumber - 1);
            org.apache.pdfbox.pdmodel.common.PDRectangle mediaBox = pdPage.getMediaBox();

            float pdfPageWidth = mediaBox.getWidth();
            float pdfPageHeight = mediaBox.getHeight();

            System.out.println("=== PDF Page Dimensions ===");
            System.out.println("PDF Page Width: " + pdfPageWidth + " points");
            System.out.println("PDF Page Height: " + pdfPageHeight + " points");
            System.out.println("\n=== Canvas Dimensions (from React) ===");
            System.out.println("Canvas Width: " + canvasWidth + " pixels");
            System.out.println("Canvas Height: " + canvasHeight + " pixels");
            System.out.println("\n=== Canvas Coordinates (from React) ===");
            System.out.println("X: " + x + ", Y: " + y + ", Width: " + width + ", Height: " + height);

            // Calculate scale factors
            float scaleX = pdfPageWidth / canvasWidth;
            float scaleY = pdfPageHeight / canvasHeight;

            System.out.println("\n=== Scale Calculation ===");
            System.out.println("Scale X: " + scaleX);
            System.out.println("Scale Y: " + scaleY);

            // Convert canvas coordinates to PDF coordinates
            // Canvas Y is from top, PDF Y is from bottom - so we need to flip
            float pdfX = x * scaleX;
            float pdfWidth = width * scaleX;
            float pdfSignatureHeight = height * scaleY;

            // The key fix: Convert canvas Y (top-origin) to PDF Y (bottom-origin)
            // Canvas Y is distance from top, so PDF Y should be: pageHeight - canvasY - height
            float pdfY = pdfPageHeight - ((y + height) * scaleY);

            System.out.println("\n=== Coordinate Conversion ===");
            System.out.println("Canvas Y from top: " + y);
            System.out.println("Canvas Y + height: " + (y + height));
            System.out.println("Scaled: " + ((y + height) * scaleY));
            System.out.println("PDF Y from bottom: " + pdfY);

            // Ensure coordinates are within page bounds
            pdfX = Math.max(0, Math.min(pdfX, pdfPageWidth - pdfWidth));
            pdfY = Math.max(0, Math.min(pdfY, pdfPageHeight - pdfSignatureHeight));
            pdfWidth = Math.min(pdfWidth, pdfPageWidth - pdfX);
            pdfSignatureHeight = Math.min(pdfSignatureHeight, pdfPageHeight - pdfY);

            // Create rectangle
            Rectangle rect = new Rectangle(
                    pdfX,
                    pdfY,
                    pdfWidth,
                    pdfSignatureHeight
            );

            System.out.println("\n=== Final PDF Coordinates ===");
            System.out.println("PDF X: " + pdfX + ", Y: " + pdfY);
            System.out.println("PDF Width: " + pdfWidth + ", Height: " + pdfSignatureHeight);
            System.out.println("Rectangle: [" + rect.getX() + ", " + rect.getY() +
                    "] to [" + (rect.getX() + rect.getWidth()) + ", " + (rect.getY() + rect.getHeight()) + "]\n");

            // Get timestamp from server
            ZonedDateTime signTime = ZonedDateTime.now(ZoneId.of("Asia/Manila"));
            String formattedTime = signTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z"));

            System.out.println("✓ Signature timestamp: " + formattedTime);

            appearance
                    .setReason("Signed Authorization")
                    .setLocation("Quezon City, Philippines")
                    .setPageRect(rect)
                    .setPageNumber(pageNumber)
                    .setReuseAppearance(false)
                    .setLayer2Text("Digitally Signed\nDate: " + formattedTime)
                    .setLayer2FontSize(7);

            // Set signature image if file exists
            if (signatureImageFile.exists() && signatureImageFile.length() > 0) {
                try {
                    appearance.setSignatureGraphic(
                            ImageDataFactory.create(signatureImageFile.getAbsolutePath())
                    );
                    appearance.setRenderingMode(
                            PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION
                    );
                    System.out.println("✓ Signature image set successfully (no transformation)");
                    System.out.println("✓ Image file size: " + signatureImageFile.length() + " bytes");
                } catch (Exception e) {
                    System.err.println("✗ Failed to set signature image: " + e.getMessage());
                    e.printStackTrace();
                    appearance.setRenderingMode(
                            PdfSignatureAppearance.RenderingMode.DESCRIPTION
                    );
                }
            } else {
                appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
                System.out.println("✗ Signature image file not found or empty");
            }

            // Unique field name per signature (important for multiple signatures)
            String fieldName = "sig_" + UUID.randomUUID().toString();
            signer.setFieldName(fieldName);

            IExternalSignature pks = new PrivateKeySignature(
                    pk,
                    DigestAlgorithms.SHA256,
                    BouncyCastleProvider.PROVIDER_NAME
            );
            IExternalDigest digest = new BouncyCastleDigest();

            // Create TSA Client if configured and enabled
            ITSAClient tsaClient = null;
            if (tsaEnabled && tsaUrl != null && !tsaUrl.isEmpty()) {
                try {
                    System.out.println("⏳ Attempting to connect to TSA: " + tsaUrl);

                    // Special handling for DICT TSA
                    if (tsaUrl.contains("govca.npki.gov.ph")) {
                        System.out.println("🇵🇭 Detected DICT TSA - using custom configuration");
                        // DICT might need specific settings
                        tsaClient = new TSAClientBouncyCastle(tsaUrl);
                        // Set digest algorithm explicitly for DICT
                        System.out.println("   Using SHA256 digest for DICT TSA");
                    } else if (tsaUsername != null && !tsaUsername.isEmpty()) {
                        tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUsername, tsaPassword);
                        System.out.println("✓ TSA Client configured with authentication: " + tsaUrl);
                    } else {
                        tsaClient = new TSAClientBouncyCastle(tsaUrl);
                        System.out.println("✓ TSA Client configured (no auth): " + tsaUrl);
                    }

                    System.out.println("✓ TSA Client created successfully");

                } catch (Exception e) {
                    System.err.println("❌ FAILED to create TSA client!");
                    System.err.println("   TSA URL: " + tsaUrl);
                    System.err.println("   Error: " + e.getClass().getName() + " - " + e.getMessage());
                    System.err.println("   Continuing WITHOUT timestamp (PDF will still be valid but no TSA timestamp)");
                    e.printStackTrace();
                    tsaClient = null; // Make sure we don't use broken client
                }
            } else {
                System.out.println("⚠ TSA disabled or not configured - signing without timestamp");
            }

            // Perform detached signing with TSA
            // Increase signature container size for TSA (default is too small)
            signer.signDetached(
                    digest,
                    pks,
                    chain,
                    null,
                    null,
                    tsaClient,  // TSA client for legally-binding timestamp
                    32768,  // Increased from 0 to 32768 bytes for TSA response
                    PdfSigner.CryptoStandard.CADES
            );

            if (tsaClient != null) {
                System.out.println("✓ PDF signed with TSA timestamp: " + formattedTime);
            } else {
                System.out.println("✓ PDF signed (no TSA timestamp): " + formattedTime);
            }
            System.out.println("✓ Output: " + dest.getAbsolutePath());

        } finally {
            if (reader != null) {
                reader.close();
            }
        }
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