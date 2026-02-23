package br.com.opt.http.secure.client.security.util;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import lombok.Builder;
import lombok.Data;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.io.IOUtils;
import org.w3c.dom.Node;

import br.com.opt.http.secure.client.security.exception.XmlJaxbHandlerException;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.Serializable;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.text.Normalizer;

@Builder
@Data
public class    XmlJaxbHandler implements Serializable {
	
    private static final long serialVersionUID = 1L;
    private Class<?> clazz;
    private Object data;
    private String xml;
    
    public String convertToString() throws XmlJaxbHandlerException{
    	try {
            JAXBContext jc = JAXBContext.newInstance(this.clazz);
            Marshaller m = jc.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
            StringWriter sw = new StringWriter();
            m.marshal(this.data, sw);
            return sw.toString();			
		} catch (JAXBException e) {
			throw new XmlJaxbHandlerException("Erro durante o processo de marshalling ou unmarshalling, convertendo um XML em um objeto Java.", e);
		}
    }

    public String convertString() throws JAXBException {
        JAXBContext jc = JAXBContext.newInstance(this.clazz);
        Marshaller m = jc.createMarshaller();
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
        StringWriter sw = new StringWriter();
        m.marshal(this.data, sw);
        return sw.toString()
                .replace("ns2:","")
                .replace(":ns2", "")
                .replace("<NFe>", "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\">")
                .replace("xmlns=\"http://www.w3.org/2000/09/xmldsig#\"", "")
                .replace("<Signature>", "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
    }
    
	public OMElement convertToOMElement() throws XmlJaxbHandlerException{
		try {
			return AXIOMUtil.stringToOM(xml);
		} catch (XMLStreamException e) {
			throw new XmlJaxbHandlerException(String.format("Error in process o XML. Detail error: [%s]", e.getMessage()), e);
		}
	}

    public Object convertToObject() throws XmlJaxbHandlerException {
    	try {
            JAXBContext jc = JAXBContext.newInstance(this.clazz);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            this.data = unmarshaller.unmarshal(IOUtils.toInputStream(xml, Charset.forName("UTF-8")));
            return this.data;			
		} catch (JAXBException e) {
			throw new XmlJaxbHandlerException("Erro durante o processo de marshalling ou unmarshalling, convertendo um XML em um objeto Java.", e);
		}
    }

    public Object convertToObjectFreeCharset() throws XmlJaxbHandlerException {
    	try {
            JAXBContext jc = JAXBContext.newInstance(this.clazz);
            Unmarshaller unmarshaller = jc.createUnmarshaller();
            this.data = unmarshaller.unmarshal(IOUtils.toInputStream(xml, Charset.defaultCharset()));
            return this.data;
		} catch (JAXBException e) {
			throw new XmlJaxbHandlerException("Erro durante o processo de marshalling ou unmarshalling, convertendo um XML em um objeto Java.", e);
		}
    }

    public String transformNodeToXmlString(Node node) throws XmlJaxbHandlerException {
    	try {
            DOMSource domSource = new DOMSource(node);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            String xml = writer.toString();
            if (xml.contains("|")) return xml.replace("|", " ");
            return xml;			
		} catch (TransformerException e) {
			throw new XmlJaxbHandlerException("Erro durante a transformação de um documento XML.", e);
		}
    }
    
	public String removeSpecialChars(String xml){
		String result = Normalizer.normalize(xml, Normalizer.Form.NFD);
	    result = result.replaceAll("[\\p{InCombiningDiacriticalMarks}]", "");
        return result;
	}
}
