package br.com.opt.http.secure.client.security.util;

import br.com.opt.http.secure.client.security.exception.NFeXmlSignerException;
import lombok.Builder;
import lombok.Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

@Builder
@Data
public class NFeXmlSigner {

    private Certificate certificate;
    private PrivateKey privateKey;
    private KeyStore.PrivateKeyEntry pkEntry;

    private String pfxFilePath;
    private String pfxPassword;
    private String xml;
    private String tagToSign;

    private void handleKeyStoreLoading() {
        try(FileInputStream inputStream = new FileInputStream(pfxFilePath)) {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            keyStore.load(inputStream, pfxPassword.toCharArray());
            Enumeration<String> aliasesEnum = keyStore.aliases();
            while (aliasesEnum.hasMoreElements()) {
                String alias = aliasesEnum.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(pfxPassword.toCharArray()));
                    privateKey = pkEntry.getPrivateKey();
                    break;
                }
            }
            this.certificate = pkEntry.getCertificate();
        }catch (UnrecoverableEntryException | KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException ex){
            throw new NFeXmlSignerException(String.format("Failed to load pfx certificate keyStore. Error %s ", ex.getMessage()));
        }
    }

    public String signXmlDocument() throws NFeXmlSignerException {
        try{

            handleKeyStoreLoading();
            disableSecureValidation();

            Document doc = parseXml(xml);
            Element element = markNodeForSigning(doc, tagToSign);
            XMLSignature signature = createSignature(element);

            signDocument(signature, element);
            return transformDocumentToString(doc);
        }catch (ParserConfigurationException | SAXException | IOException | NoSuchAlgorithmException |
                InvalidAlgorithmParameterException | XMLSignatureException | TransformerException | MarshalException ex){
            throw new NFeXmlSignerException(String.format("Failed to load pfx certificate keyStore. Error %s ", ex.getMessage()));
        }
    }

    private void disableSecureValidation() {
        System.setProperty("org.jcp.xml.dsig.secureValidation", "false");
    }

    private Document parseXml(String xml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private Element markNodeForSigning(Document doc, String nodeToAssign) {
        NodeList eventNode = doc.getElementsByTagName(nodeToAssign);
        Element element = (Element) eventNode.item(0);
        element.setIdAttribute("Id", true);
        return element;
    }

    private XMLSignature createSignature(Element element)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        List<Transform> transforms = List.of(
                fac.newTransform(CanonicalizationMethod.ENVELOPED, (TransformParameterSpec) null),
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null)
        );

        DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA1, null);
        Reference reference = fac.newReference("#" + element.getAttribute("Id"), digestMethod, transforms, null, null);

        SignedInfo signedInfo = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null),
                Collections.singletonList(reference)
        );

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509Data = kif.newX509Data(Collections.singletonList(certificate));
        KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509Data));

        return fac.newXMLSignature(signedInfo, keyInfo);
    }

    private void signDocument(XMLSignature signature, Element element)
            throws MarshalException, XMLSignatureException {
        DOMSignContext dsc = new DOMSignContext(privateKey, element.getParentNode());
        signature.sign(dsc);
    }

    private String transformDocumentToString(Document doc) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        trans.setOutputProperty(OutputKeys.INDENT, "no");

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        return os.toString(StandardCharsets.UTF_8);
    }
}
