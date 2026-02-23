package br.com.opt.http.secure.client.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.net.ssl.SSLContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.com.opt.http.secure.client.security.exception.ClientSecurityException;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TlsSecurityConfigurator {
	
    protected SSLContext sslContext;
    protected String pfxFilePath;
    protected String pfxPassword;

    @Builder.Default
    protected String prefixPath = (System.getenv("CERTIFICATE_PATH") != null ? System.getenv("CERTIFICATE_PATH") :
            "." + File.separator + ".." + File.separator + "environment" + File.separator + "cert" + File.separator);
    @Builder.Default
    protected String cacerts = "cacerts_nfe.jks";
    @Builder.Default
    protected String keyStoreType = "PKCS12";
    @Builder.Default
    protected String type = "JKS";
    @Builder.Default
    protected String trustStorePass = "changeit";

	public void setupSslCertificates() throws ClientSecurityException {
        try {
        	Security.addProvider(new BouncyCastleProvider());
            SSLContext.getInstance("TLSv1.3");

            System.setProperty("https.protocols", "TLSv1.3");
        	System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
            System.setProperty("java.protocol.handler.pkgs", "com.sun.net.ssl.internal.www.protocol");
            System.setProperty("javax.net.ssl.keyStoreType", this.keyStoreType);

            System.clearProperty("javax.net.ssl.keyStore");
            System.clearProperty("javax.net.ssl.keyStorePassword");
            System.clearProperty("javax.net.ssl.trustStore");
            String cert = (pfxFilePath.contains(File.separator + "cert" + File.separator) ? pfxFilePath : this.prefixPath+ pfxFilePath);
            System.setProperty("javax.net.ssl.keyStore", cert);
            System.setProperty("javax.net.ssl.keyStorePassword", pfxPassword);

            System.setProperty("javax.net.ssl.trustStoreType", this.type);
            System.setProperty("javax.net.ssl.trustStore", this.prefixPath + this.cacerts);

            System.setProperty("javax.net.debug", "all");
            
        } catch (NoSuchAlgorithmException ex) {
            throw new ClientSecurityException(String.format("Erro ao configurar o algoritmo criptográfico: o algoritmo ou "
            		+ "provedor especificado não está disponível. [Excecao] = %s, [Erro] = %s", ex.getClass().getName(), ex.getMessage()), ex);
        }
    }
}
