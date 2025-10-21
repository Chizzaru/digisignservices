package com.github.ws_ncip_pnpki.repository;

import com.github.ws_ncip_pnpki.model.SigningAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<SigningAuditLog, Long> {

    List<SigningAuditLog> findByBatchId(String batchId);

    List<SigningAuditLog> findByUserEmailOrderByTimestampDesc(String userEmail);

    List<SigningAuditLog> findAllByOrderByTimestampDesc();

    List<SigningAuditLog> findByStatus(String status);
}