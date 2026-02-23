package br.com.opt.http.secure.client.security;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.TrustStrategy;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import br.com.opt.http.secure.client.security.commons.ClientHttpsSecurityCommons;
import br.com.opt.http.secure.client.security.exception.ClientSecurityException;
import br.com.opt.http.secure.client.security.util.XmlJaxbHandler;

public class ClientHttpsSecurity extends ClientHttpsSecurityCommons {

    public ClientHttpsSecurity(String pfxFilePath, String pfxPassword, String url, String envelope, String soapAction, boolean soap12, String httpVerb) {
        super.url = url;
        super.envelope = envelope;
        super.soapAction = soapAction;
        super.soap12 = soap12;
        super.pfxFilePath = pfxFilePath;
        super.pfxPassword = pfxPassword;
        super.httpVerb = httpVerb;
    }

    public ClientHttpsSecurity(String filePfx, String passPfx, String url) {
        super.url = url;
        super.pfxFilePath = filePfx;
        super.pfxPassword = passPfx;
    }

    private HttpPost post(String url) {
        return new HttpPost(url);
    }

    private HttpGet get(String url) {
        return new HttpGet(url);
    }
    
    private RequestConfig applyConfigRequest() {
        return RequestConfig.custom().setSocketTimeout(60000)
                .setConnectTimeout(60000)
                .build();
    }

    public Registry<ConnectionSocketFactory> setupTlsSocketFactory() throws ClientSecurityException {
        try {
            TrustStrategy trustStrategy = (cert, authType) -> true;
            boolean isTrusted = trustStrategy.isTrusted(this.loadPfxCertificate(), TrustManagerFactory.getDefaultAlgorithm());
            if (!isTrusted) throw new ClientSecurityException("Invalid credentials!");
            SSLContext sslContext = this.sslContextFactory("TLS");
            SSLConnectionSocketFactory sslContextFactory = new SSLConnectionSocketFactory(sslContext);
            Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("https", sslContextFactory).build();
            return socketFactoryRegistry;            
        } catch (CertificateException ex) {
            throw new ClientSecurityException(ex.getMessage(), ex);
        }
    }
    
    private BasicHeader buildBasicHeaderContentType() {
    	BasicHeader basic = null;
    	if(soap12) {
    		basic = new BasicHeader("Content-type", "application/soap+xml; charset=utf-8");
    	}else {
    		basic = new BasicHeader("Content-type", "text/xml");
    	}
    	return basic;
    }
    
    private Document invokeClientPost() throws ClientSecurityException{
        try (BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(this.setupTlsSocketFactory());
             CloseableHttpClient httpClient = HttpClientBuilder.create()
                     .setDefaultRequestConfig(this.applyConfigRequest())
                     .setConnectionManager(connectionManager)
                     .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build()) {
            HttpPost httpPost = post(url.toLowerCase().contains("?wsdl") ? url : url+"?wsdl");
            httpPost.setEntity(new StringEntity(envelope));
            httpPost.addHeader(buildBasicHeaderContentType());
            if (soapAction != null) httpPost.addHeader("SOAPAction", soapAction);
        	CloseableHttpResponse response = httpClient.execute(httpPost);
        	handlerExecption(response);
            HttpEntity entity = response.getEntity();
            return buildDocument(entity);
        } catch (IOException | UnsupportedOperationException | TransformerException | SAXException | ParserConfigurationException ex) {
            throw new ClientSecurityException(String.format("Error sending data via POST. URL = [%s], Error = [%s]", url, ex.getMessage()), ex);
        }
    }
    
    private Document invokeClientGet() throws ClientSecurityException {
    	try (BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(this.setupTlsSocketFactory());
             CloseableHttpClient httpClient = HttpClientBuilder.create()
                     .setDefaultRequestConfig(this.applyConfigRequest())
                     .setConnectionManager(connectionManager)
                     .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build()) {
        	HttpGet httpGet = get(url.toLowerCase().contains("?wsdl") ? url : url+"?wsdl");
        	httpGet.addHeader(buildBasicHeaderContentType());
        	if (soapAction != null) httpGet.addHeader("SOAPAction", soapAction);
    		CloseableHttpResponse response = httpClient.execute(httpGet);
        	handlerExecption(response);
            HttpEntity entity = response.getEntity();
            return buildDocument(entity);
        } catch (IOException | UnsupportedOperationException | TransformerException | SAXException | ParserConfigurationException ex) {
            throw new ClientSecurityException(String.format("Error sending data via GET. URL = [%s], Error = [%s]", url, ex.getMessage()), ex);
        }
    }
    
    private void handlerExecption(CloseableHttpResponse response) throws ClientSecurityException {
        int statusCode = response.getStatusLine().getStatusCode();
    	String statusDescription = response.getStatusLine().getReasonPhrase();
        if (statusCode != HttpStatus.SC_OK && statusCode != HttpStatus.SC_CREATED && statusCode != HttpStatus.SC_UNPROCESSABLE_ENTITY) {
        	throw new ClientSecurityException("Error when making the request, message: Code \": " + statusCode + " Description: " + statusDescription + "\"");
        }    	
    }
    
    private Document buildDocument(HttpEntity entity) throws TransformerException, UnsupportedOperationException, SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(entity.getContent());

        DOMSource domSource = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);
        return doc;
    }
    
    public String requestAndExtractXmlTag(String tag) throws ClientSecurityException {
    	Document doc = switch (httpVerb) {
			case "GET" -> this.invokeClientGet();
			case "POST" -> this.invokeClientPost();
			default -> throw new IllegalArgumentException("HTTP verb not implemented: " + httpVerb);
    	};
        NodeList nodeList   = doc.getElementsByTagName(tag) ;
        return XmlJaxbHandler.builder().build().transformNodeToXmlString(nodeList.item(0).getChildNodes().item(0));
    }
}
