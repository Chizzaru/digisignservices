package com.github.ws_ncip_pnpki.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

/**
 * Represents a request for signing a PDF document using the PNPKI digital certificate.
 * <p>
 * This DTO (Data Transfer Object) is used by the REST API to receive client input
 * required for digitally signing a PDF file. The input includes the certificate file,
 * its password, and positioning details for the signature in the PDF.
 * </p>
 *
 * <h2>Field Descriptions:</h2>
 * <ul>
 *   <li><b>pkcsFile</b> — Certificate file in <code>.p12</code> format (must not be {@code null}).</li>
 *   <li><b>pkcsPassword</b> — Password to unlock the <code>.p12</code> certificate file (must not be {@code null}).</li>
 *   <li><b>pdfSrc</b> — Path or name of the source PDF document to be signed.</li>
 *   <li><b>pdfDest</b> — Path or name of the output (signed) PDF document.</li>
 *   <li><b>pageNumber</b> — Page index in the PDF where the signature will appear (0-based or 1-based depending on implementation).</li>
 *   <li><b>x</b> — Horizontal position of the signature rectangle (in points or pixels).</li>
 *   <li><b>y</b> — Vertical position of the signature rectangle.</li>
 *   <li><b>width</b> — Width of the signature field (in points or pixels).</li>
 *   <li><b>height</b> — Height of the signature field.</li>
 *   <li><b>append</b> — Whether to apply the signature in append mode (i.e., without invalidating existing signatures).</li>
 * </ul>
 *
 * <p><b>Usage:</b> Typically sent as a multipart/form-data POST request where
 * {@code pkcsFile} is the file upload and other fields are form fields.</p>
 *
 * @author Christian C. Cernechez
 * @version 1.1
 */
@Data
public class PNPKISigningRequest {

    /** Certificate file (.p12) issued by PNPKI. Must not be null. */
    private MultipartFile pkcsFile;

    /** Password for the PKCS#12 certificate file. Must not be null. */
    private String pkcsPassword;

    /** Source PDF file path to be signed. */
    private String pdfSrc;

    /** Destination PDF path where the signed file will be stored. */
    private String pdfDest;

    /** Page number in the PDF where the signature will appear. */
    private int pageNumber;

    /** X-axis coordinate of the signature field. */
    private float x;

    /** Y-axis coordinate of the signature field. */
    private float y;

    /** Width of the signature area. */
    private float width;

    /** Height of the signature area. */
    private float height;

    /** Whether to use append mode when stamping the signature. */
    private boolean append;
}
