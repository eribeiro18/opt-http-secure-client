package br.com.opt.http.secure.client.security.commons;

import javax.net.ssl.*;

import br.com.opt.http.secure.client.security.TlsSecurityConfigurator;
import br.com.opt.http.secure.client.security.exception.ClientSecurityException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public abstract class ClientHttpsSecurityCommons extends TlsSecurityConfigurator {

    protected String url;
    protected String envelope;
    protected String soapAction;
    protected boolean soap12;
    protected String httpVerb;

    private KeyStore trustStore;
    private KeyStore keyStore;
    private KeyStore.PrivateKeyEntry pkEntry;
    private X509Certificate[] certificate;

    public X509Certificate[] loadPfxCertificate() throws ClientSecurityException {
    	String cert = (pfxFilePath.contains(File.separator + "cert" + File.separator) ? pfxFilePath : this.prefixPath+ pfxFilePath);
        try (InputStream inputStream = new FileInputStream(cert)){
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(inputStream, this.pfxPassword.toCharArray());
            Enumeration<String> aliasesEnum = keyStore.aliases();
            while (aliasesEnum.hasMoreElements()) {
                String alias = aliasesEnum.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    this.pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(pfxPassword.toCharArray()));
                    break;
                }
            }
            this.certificate = (X509Certificate[]) pkEntry.getCertificateChain();
            return this.certificate;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException ex) {
            throw new ClientSecurityException(String.format("Erro ao acessar o KeyStore - pfx: falha ao configurar o algoritmo, "
            		+ "recuperar a entrada ou manipular o armazenamento de chaves [Excecao] = %s, [error] = %s", ex.getClass().getName(), ex.getMessage()), ex);
        } 
    }

    private void loadKeyStore() throws ClientSecurityException {
        if (pfxPassword != null) {
        	String cert = (pfxFilePath.contains(File.separator + "cert" + File.separator) ? pfxFilePath : this.prefixPath+ pfxFilePath);
            try (FileInputStream fisTrust = new FileInputStream(cert)) {
            	keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(fisTrust, pfxPassword.toCharArray());
            } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException ex) {
                throw new ClientSecurityException(String.format("Erro ao carregar o KeyStore: ocorreu um problema com o certificado, "
                		+ "configuração do algoritmo, leitura de dados ou manipulação do armazenamento de chaves, [Excecao] = %s, [error] = %s", ex.getClass().getName(), ex.getMessage()), ex);
            } 
        }
    }

    private KeyManagerFactory configTrustStore() throws ClientSecurityException{
    	handleKeyStoreLoading();
    	return initTrustStore();
    }

    private void handleKeyStoreLoading() throws ClientSecurityException {
        try (FileInputStream fisTrustStore = new FileInputStream(this.prefixPath + cacerts)) {
        	trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(fisTrustStore, trustStorePass.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException ex) {
            throw new ClientSecurityException(String.format("Erro durante a manipulação do KeyStore: ocorreu um problema ao acessar o certificado, "
            		+ "configurar o algoritmo, realizar operações de I/O ou manipular o armazenamento de chaves. [Excecao] = %s, [error] = %s", ex.getClass().getName(), ex.getMessage()), ex);
        }
    }
    
    private KeyManagerFactory initTrustStore() throws ClientSecurityException{
        try {
        	KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFactory.init(keyStore, this.pfxPassword.toCharArray());
            return keyFactory;
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException ex) {
            throw new ClientSecurityException(String.format("Erro ao acessar a chave no KeyStore: falha ao recuperar a chave, configurar o algoritmo "
            		+ "ou manipular o armazenamento de chaves.  [Excecao] = %s, [Error] = %s", ex.getClass().getName(), ex.getMessage()), ex);
        }
    }
    
    public SSLContext sslContextFactory(String sslContextTier) throws ClientSecurityException {
        try {
            this.loadKeyStore();
            KeyManager[] keyManagers = this.configTrustStore().getKeyManagers();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            TrustManager[] trustManager = trustManagerFactory.getTrustManagers();
            if (keyManagers != null) {
                sslContext = SSLContext.getInstance(sslContextTier);
                sslContext.init(keyManagers, trustManager, null);
                SSLContext.setDefault(sslContext);
            }
            return this.sslContext;
        } catch (KeyStoreException | NoSuchAlgorithmException | KeyManagementException ex) {
            throw new ClientSecurityException(ex.getMessage());
        } 
    }
}
