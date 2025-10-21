package com.github.ws_ncip_pnpki.dto;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

@Data
public class PKCS12Request {
    private MultipartFile pkcsFile;
    private String pkcsPassword;
}
