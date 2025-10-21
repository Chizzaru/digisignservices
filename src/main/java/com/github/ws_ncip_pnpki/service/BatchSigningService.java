package com.github.ws_ncip_pnpki.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.*;
import java.util.concurrent.*;

@Service
public class BatchSigningService {

    @Autowired
    private PdfSigningService pdfSigningService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private EmailNotificationService emailNotificationService;

    private final ExecutorService executorService = Executors.newFixedThreadPool(5);

    /**
     * Sign multiple PDFs in parallel
     */
    public Map<String, Object> signMultiplePdfs(
            List<MultipartFile> pdfDocuments,
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
            String userEmail) throws Exception {

        String batchId = UUID.randomUUID().toString();
        List<Future<Map<String, Object>>> futures = new ArrayList<>();

        System.out.println("🔄 Starting batch signing for " + pdfDocuments.size() + " documents");
        System.out.println("📦 Batch ID: " + batchId);

        // Submit all signing tasks
        for (int i = 0; i < pdfDocuments.size(); i++) {
            final MultipartFile pdf = pdfDocuments.get(i);
            final int index = i;

            Future<Map<String, Object>> future = executorService.submit(() -> {
                Map<String, Object> result = new HashMap<>();
                result.put("originalFilename", pdf.getOriginalFilename());
                result.put("index", index);

                try {
                    String signedFileName = pdfSigningService.signPdf(
                            pdf,
                            signatureImage,
                            certificateFile,
                            pageNumber,
                            x, y, width, height,
                            canvasWidth, canvasHeight,
                            password,""
                    );

                    result.put("success", true);
                    result.put("signedFilename", signedFileName);

                    // Log the signing
                    auditLogService.logSigning(
                            batchId,
                            pdf.getOriginalFilename(),
                            signedFileName,
                            userEmail,
                            "SUCCESS"
                    );

                    System.out.println("✓ Signed: " + pdf.getOriginalFilename());

                } catch (Exception e) {
                    result.put("success", false);
                    result.put("error", e.getMessage());

                    auditLogService.logSigning(
                            batchId,
                            pdf.getOriginalFilename(),
                            null,
                            userEmail,
                            "FAILED: " + e.getMessage()
                    );

                    System.err.println("✗ Failed: " + pdf.getOriginalFilename() + " - " + e.getMessage());
                }

                return result;
            });

            futures.add(future);
        }

        // Collect results
        List<Map<String, Object>> results = new ArrayList<>();
        int successCount = 0;
        int failureCount = 0;

        for (Future<Map<String, Object>> future : futures) {
            try {
                Map<String, Object> result = future.get(5, TimeUnit.MINUTES);
                results.add(result);

                if ((Boolean) result.get("success")) {
                    successCount++;
                } else {
                    failureCount++;
                }
            } catch (TimeoutException e) {
                Map<String, Object> timeoutResult = new HashMap<>();
                timeoutResult.put("success", false);
                timeoutResult.put("error", "Timeout after 5 minutes");
                results.add(timeoutResult);
                failureCount++;
            } catch (Exception e) {
                Map<String, Object> errorResult = new HashMap<>();
                errorResult.put("success", false);
                errorResult.put("error", e.getMessage());
                results.add(errorResult);
                failureCount++;
            }
        }

        // Send email notification
        if (userEmail != null && !userEmail.isEmpty()) {
            emailNotificationService.sendBatchSigningNotification(
                    userEmail,
                    batchId,
                    pdfDocuments.size(),
                    successCount,
                    failureCount
            );
        }

        Map<String, Object> batchResult = new HashMap<>();
        batchResult.put("batchId", batchId);
        batchResult.put("totalDocuments", pdfDocuments.size());
        batchResult.put("successCount", successCount);
        batchResult.put("failureCount", failureCount);
        batchResult.put("results", results);

        System.out.println("✓ Batch signing complete: " + successCount + " succeeded, " + failureCount + " failed");

        return batchResult;
    }

    /**
     * Get batch signing status
     */
    public Map<String, Object> getBatchStatus(String batchId) {
        return auditLogService.getBatchStatus(batchId);
    }
}