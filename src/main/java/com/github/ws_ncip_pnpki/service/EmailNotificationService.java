package com.github.ws_ncip_pnpki.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class EmailNotificationService {

    @Autowired
    private JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.url:http://localhost:5173}")
    private String appUrl;

    /**
     * Send batch signing completion notification
     */
    public void sendBatchSigningNotification(
            String toEmail,
            String batchId,
            int totalDocuments,
            int successCount,
            int failureCount) {

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("PDF Batch Signing Complete - Batch ID: " + batchId);

            String htmlContent = buildBatchSigningEmail(batchId, totalDocuments, successCount, failureCount);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            System.out.println("✓ Email notification sent to: " + toEmail);

        } catch (Exception e) {
            System.err.println("✗ Failed to send email: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Send single document signing notification
     */
    public void sendSigningNotification(
            String toEmail,
            String originalFilename,
            String signedFilename,
            boolean hasTimestamp) {

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("PDF Document Signed: " + originalFilename);

            String htmlContent = buildSigningEmail(originalFilename, signedFilename, hasTimestamp);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            System.out.println("✓ Email notification sent to: " + toEmail);

        } catch (Exception e) {
            System.err.println("✗ Failed to send email: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Send verification result notification
     */
    public void sendVerificationNotification(
            String toEmail,
            String filename,
            boolean allValid,
            int signatureCount) {

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("PDF Verification Result: " + filename);

            String htmlContent = buildVerificationEmail(filename, allValid, signatureCount);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            System.out.println("✓ Email notification sent to: " + toEmail);

        } catch (Exception e) {
            System.err.println("✗ Failed to send email: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String buildBatchSigningEmail(String batchId, int total, int success, int failure) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #4CAF50; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
                        .content { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
                        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
                        .stat { text-align: center; padding: 15px; background: white; border-radius: 5px; flex: 1; margin: 0 5px; }
                        .stat-number { font-size: 32px; font-weight: bold; color: #4CAF50; }
                        .failure { color: #f44336; }
                        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
                        .button { display: inline-block; padding: 10px 20px; background: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin-top: 10px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>📄 Batch Signing Complete</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>Your batch signing operation has been completed.</p>
                            
                            <div style="background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 15px 0;">
                                <strong>Batch ID:</strong> %s<br>
                                <strong>Completed:</strong> %s
                            </div>
                            
                            <div class="stats">
                                <div class="stat">
                                    <div class="stat-number">%d</div>
                                    <div>Total Documents</div>
                                </div>
                                <div class="stat">
                                    <div class="stat-number">%d</div>
                                    <div>✓ Success</div>
                                </div>
                                <div class="stat">
                                    <div class="stat-number failure">%d</div>
                                    <div>✗ Failed</div>
                                </div>
                            </div>
                            
                            <p>You can download your signed documents from the application.</p>
                            
                            <a href="%s" class="button">View Signed Documents</a>
                            
                            <div class="footer">
                                <p>This is an automated notification from the PDF Signing Service.</p>
                                <p>If you did not request this action, please contact support immediately.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """, batchId, timestamp, total, success, failure, appUrl);
    }

    private String buildSigningEmail(String original, String signed, boolean hasTimestamp) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String tsaStatus = hasTimestamp ? "✓ Included" : "✗ Not included";
        String tsaColor = hasTimestamp ? "#4CAF50" : "#ff9800";

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #2196F3; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
                        .content { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
                        .info-box { background: white; padding: 15px; border-left: 4px solid #2196F3; margin: 15px 0; }
                        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>✅ Document Signed Successfully</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>Your PDF document has been digitally signed.</p>
                            
                            <div class="info-box">
                                <strong>Original File:</strong> %s<br>
                                <strong>Signed File:</strong> %s<br>
                                <strong>Signed At:</strong> %s<br>
                                <strong>TSA Timestamp:</strong> <span style="color: %s;">%s</span>
                            </div>
                            
                            <p>The document is now ready for download and can be verified at any time.</p>
                            
                            <div class="footer">
                                <p>This is an automated notification from the PDF Signing Service.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """, original, signed, timestamp, tsaColor, tsaStatus);
    }

    private String buildVerificationEmail(String filename, boolean valid, int count) {
        String status = valid ? "✓ All Signatures Valid" : "⚠ Issues Found";
        String color = valid ? "#4CAF50" : "#f44336";

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: %s; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
                        .content { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
                        .status-box { background: white; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px; }
                        .status-text { font-size: 24px; font-weight: bold; color: %s; }
                        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔍 Verification Complete</h1>
                        </div>
                        <div class="content">
                            <p>Hello,</p>
                            <p>Verification has been completed for your PDF document.</p>
                            
                            <div class="status-box">
                                <div><strong>File:</strong> %s</div>
                                <div style="margin: 15px 0;">
                                    <div class="status-text">%s</div>
                                </div>
                                <div><strong>Signatures Found:</strong> %d</div>
                            </div>
                            
                            <p>For detailed verification results, please check the application.</p>
                            
                            <div class="footer">
                                <p>This is an automated notification from the PDF Signing Service.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """, color, color, filename, status, count);
    }
}