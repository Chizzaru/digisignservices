
package com.github.ws_ncip_pnpki.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.ws_ncip_pnpki.service.PdfSigningService;
import com.github.ws_ncip_pnpki.service.BatchSigningService;
import com.github.ws_ncip_pnpki.service.AuditLogService;
import com.github.ws_ncip_pnpki.service.EmailNotificationService;
import com.github.ws_ncip_pnpki.util.PnpkiUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/")
public class SampleController {

    @Autowired
    private PdfSigningService pdfSigningService;

    @Autowired
    private BatchSigningService batchSigningService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private EmailNotificationService emailNotificationService;

    @Autowired
    private ObjectMapper objectMapper; // Add this

    @Value("${pdf.signing.output-dir:./signed-documents}")
    private String outputDir;

    @GetMapping(value = "sample", produces = "application/json")
    public ResponseEntity<?> sample() {
        File file = new File("E:/KEY/My Key/CERNECHEZ+CHRISTIAN+CRUZANA.p12");
        String password = "Ccernechez1996";
        try {
            PnpkiUtil.loadPkcs12(file, password);
            return ResponseEntity.ok("Valid Certificate");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @PostMapping(value = "sign-document-multi")
    public ResponseEntity<?> signDocumentMultiPage(
            @RequestParam("pdfDocument") MultipartFile pdfDocument,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("certificateFile") MultipartFile certificateFile,
            @RequestParam("signaturePlacements") String signaturePlacementsJson,
            @RequestParam("canvasWidth") float canvasWidth,
            @RequestParam("canvasHeight") float canvasHeight,
            @RequestParam("password") String password,
            @RequestParam(value = "location", defaultValue = "Unknown Location") String location) {  // Add location parameter

        try {
            List<PdfSigningService.SignaturePlacement> placements =
                    objectMapper.readValue(signaturePlacementsJson,
                            new TypeReference<List<PdfSigningService.SignaturePlacement>>() {});

            String signedFileName = pdfSigningService.signPdfMultiPage(
                    pdfDocument, signatureImage, certificateFile,
                    placements, canvasWidth, canvasHeight, password, location);

            return ResponseEntity.ok().body(Map.of(
                    "message", "Document signed successfully",
                    "signedFile", signedFileName,
                    "pagesSigned", placements.size()
            ));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Signing failed: " + e.getMessage()
            ));
        }
    }



    /**
     * Batch sign multiple PDF documents
     */
    @PostMapping(value = "batch-sign-documents")
    public ResponseEntity<?> batchSignDocuments(
            @RequestParam("pdfDocuments") List<MultipartFile> pdfDocuments,
            @RequestParam("signatureImage") MultipartFile signatureImage,
            @RequestParam("certificateFile") MultipartFile certificateFile,
            @RequestParam("page") int pageNumber,
            @RequestParam("x") float x,
            @RequestParam("y") float y,
            @RequestParam("width") float width,
            @RequestParam("height") float height,
            @RequestParam("canvasWidth") float canvasWidth,
            @RequestParam("canvasHeight") float canvasHeight,
            @RequestParam("password") String password,
            @RequestParam(value = "userEmail", required = false) String userEmail) {

        try {
            Map<String, Object> result = batchSigningService.signMultiplePdfs(
                    pdfDocuments,
                    signatureImage,
                    certificateFile,
                    pageNumber,
                    x, y, width, height,
                    canvasWidth, canvasHeight,
                    password,
                    userEmail
            );

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "batch", result
            ));

        } catch (Exception e) {
            System.err.println("❌ Error in batch signing:");
            e.printStackTrace();

            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Get batch signing status
     */
    @GetMapping(value = "batch-status/{batchId}")
    public ResponseEntity<?> getBatchStatus(@PathVariable String batchId) {
        try {
            Map<String, Object> status = batchSigningService.getBatchStatus(batchId);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "status", status
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Get user's signing history
     */
    @GetMapping(value = "audit/user/{email}")
    public ResponseEntity<?> getUserHistory(
            @PathVariable String email,
            @RequestParam(defaultValue = "50") int limit) {
        try {
            List<Map<String, Object>> history = auditLogService.getUserHistory(email, limit);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "history", history
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Get all audit logs (admin)
     */
    @GetMapping(value = "audit/all")
    public ResponseEntity<?> getAllLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        try {
            List<Map<String, Object>> logs = auditLogService.getAllLogs(page, size);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "logs", logs,
                    "page", page,
                    "size", size
            ));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Verify signatures in a PDF document
     */
    @PostMapping(value = "verify-document")
    public ResponseEntity<?> verifyDocument(
            @RequestParam("pdfDocument") MultipartFile pdfDocument,
            @RequestParam(value = "userEmail", required = false) String userEmail) {

        try {
            // Save uploaded file to temporary location
            File tempPdfFile = File.createTempFile("verify_pdf_", ".pdf");
            pdfDocument.transferTo(tempPdfFile);

            Map<String, Object> verificationResult = pdfSigningService.verifySignatures(tempPdfFile);

            // Log the verification
            auditLogService.logVerification(
                    pdfDocument.getOriginalFilename(),
                    userEmail,
                    (Boolean) verificationResult.get("allValid"),
                    (Integer) verificationResult.get("signatureCount")
            );

            // Clean up
            tempPdfFile.delete();

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "verification", verificationResult
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Check if a PDF has signatures (useful before adding another signature)
     */
    @PostMapping(value = "check-signatures")
    public ResponseEntity<?> checkSignatures(
            @RequestParam("pdfDocument") MultipartFile pdfDocument) {

        try {
            File tempPdfFile = File.createTempFile("check_pdf_", ".pdf");
            pdfDocument.transferTo(tempPdfFile);

            boolean hasSignatures = pdfSigningService.hasSignatures(tempPdfFile);

            tempPdfFile.delete();

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "hasSignatures", hasSignatures
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }

    /**
     * Download a signed document
     */
    @GetMapping(value = "download/{filename}")
    public ResponseEntity<?> downloadDocument(@PathVariable String filename) {
        try {
            File file = new File(outputDir, filename);
            if (!file.exists()) {
                return ResponseEntity.status(404).body(Map.of(
                        "success", false,
                        "error", "File not found"
                ));
            }

            org.springframework.core.io.Resource resource =
                    new org.springframework.core.io.FileSystemResource(file);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                    .header("Content-Type", "application/pdf")
                    .contentLength(file.length())
                    .body(resource);

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "error", e.getMessage()
            ));
        }
    }
}