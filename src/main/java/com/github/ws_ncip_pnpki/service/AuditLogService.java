package com.github.ws_ncip_pnpki.service;

import com.github.ws_ncip_pnpki.model.SigningAuditLog;
import com.github.ws_ncip_pnpki.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    /**
     * Log a signing event
     */
    public void logSigning(
            String batchId,
            String originalFilename,
            String signedFilename,
            String userEmail,
            String status) {

        SigningAuditLog log = new SigningAuditLog();
        log.setBatchId(batchId);
        log.setOriginalFilename(originalFilename);
        log.setSignedFilename(signedFilename);
        log.setUserEmail(userEmail);
        log.setStatus(status);
        log.setTimestamp(LocalDateTime.now());
        log.setIpAddress(getCurrentIpAddress());

        auditLogRepository.save(log);
    }

    /**
     * Log a verification event
     */
    public void logVerification(
            String filename,
            String userEmail,
            boolean isValid,
            int signatureCount) {

        SigningAuditLog log = new SigningAuditLog();
        log.setOriginalFilename(filename);
        log.setUserEmail(userEmail);
        log.setStatus(isValid ? "VERIFICATION_SUCCESS" : "VERIFICATION_FAILED");
        log.setTimestamp(LocalDateTime.now());
        log.setIpAddress(getCurrentIpAddress());
        log.setAdditionalInfo("Signatures found: " + signatureCount);

        auditLogRepository.save(log);
    }

    /**
     * Get batch signing status
     */
    public Map<String, Object> getBatchStatus(String batchId) {
        List<SigningAuditLog> logs = auditLogRepository.findByBatchId(batchId);

        if (logs.isEmpty()) {
            return Map.of("found", false);
        }

        long successCount = logs.stream()
                .filter(log -> log.getStatus().equals("SUCCESS"))
                .count();

        long failureCount = logs.stream()
                .filter(log -> log.getStatus().startsWith("FAILED"))
                .count();

        Map<String, Object> status = new HashMap<>();
        status.put("found", true);
        status.put("batchId", batchId);
        status.put("totalDocuments", logs.size());
        status.put("successCount", successCount);
        status.put("failureCount", failureCount);
        status.put("timestamp", logs.get(0).getTimestamp());
        status.put("userEmail", logs.get(0).getUserEmail());
        status.put("logs", logs.stream()
                .map(this::convertToMap)
                .collect(Collectors.toList()));

        return status;
    }

    /**
     * Get audit history for a user
     */
    public List<Map<String, Object>> getUserHistory(String userEmail, int limit) {
        List<SigningAuditLog> logs = auditLogRepository.findByUserEmailOrderByTimestampDesc(userEmail);

        return logs.stream()
                .limit(limit)
                .map(this::convertToMap)
                .collect(Collectors.toList());
    }

    /**
     * Get all audit logs (admin only)
     */
    public List<Map<String, Object>> getAllLogs(int page, int size) {
        List<SigningAuditLog> logs = auditLogRepository.findAllByOrderByTimestampDesc();

        return logs.stream()
                .skip((long) page * size)
                .limit(size)
                .map(this::convertToMap)
                .collect(Collectors.toList());
    }

    private Map<String, Object> convertToMap(SigningAuditLog log) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", log.getId());
        map.put("batchId", log.getBatchId());
        map.put("originalFilename", log.getOriginalFilename());
        map.put("signedFilename", log.getSignedFilename());
        map.put("userEmail", log.getUserEmail());
        map.put("status", log.getStatus());
        map.put("timestamp", log.getTimestamp());
        map.put("ipAddress", log.getIpAddress());
        map.put("additionalInfo", log.getAdditionalInfo());
        return map;
    }

    private String getCurrentIpAddress() {
        // In a real application, get this from HttpServletRequest
        try {
            return java.net.InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "unknown";
        }
    }
}