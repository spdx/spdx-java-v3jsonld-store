/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.core.CoreModelObject;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedValue;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.library.model.v3.core.Agent;
import org.spdx.library.model.v3.core.CreationInfo;
import org.spdx.library.model.v3.core.Person;
import org.spdx.library.model.v3.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * @author Gary O'Neall
 *
 */
public class JsonLDDeserializerTest {

	IModelStore modelStore;
	ObjectMapper mapper;
	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		SpdxModelFactory.init();
		modelStore = new InMemSpdxStore();
		mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDDeserializer#deserializeGraph(com.fasterxml.jackson.databind.JsonNode)}.
	 */
	@Test
	public void testDeserializeGraph() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDDeserializer#deserializeElement(com.fasterxml.jackson.databind.JsonNode)}.
	 * @throws InvalidSPDXAnalysisException 
	 * @throws GenerationException 
	 */
	@Test
	public void testDeserializeElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDDeserializer deserializer = new JsonLDDeserializer(modelStore);
		
		String specVersion = "3.0.0";
		String created = "2024-07-18T12:00:00Z";
		String personSpdxId = "https://this/is/a/person";
		String personName = "My Name Is Gary";
		
		ObjectNode creationInfoNode = mapper.createObjectNode();
		creationInfoNode.set("type", new TextNode("CreationInfo"));
		creationInfoNode.set("specVersion", new TextNode(specVersion));
		creationInfoNode.set("created", new TextNode(created));
		ArrayNode createdBysNode = mapper.createArrayNode();
		createdBysNode.add(new TextNode(personSpdxId));
		creationInfoNode.set("createdBy", createdBysNode);
		ObjectNode personNode = mapper.createObjectNode();
		personNode.set("type", new TextNode("Person"));
		personNode.set("spdxId", new TextNode(personSpdxId));
		personNode.set("name", new TextNode(personName));
		personNode.set("creationInfo", creationInfoNode);
		
		TypedValue result = deserializer.deserializeElement(personNode);
		assertEquals(specVersion, result.getSpecVersion());
		assertEquals(SpdxConstantsV3.CORE_PERSON, result.getType());
		assertEquals(personSpdxId, result.getObjectUri());
		
		CoreModelObject inflated = SpdxModelFactory.inflateModelObject(modelStore, personSpdxId, SpdxConstantsV3.CORE_PERSON, null, specVersion, false, "");
		assertTrue(inflated instanceof Person);
		Person personResult = (Person)inflated;
		assertEquals(specVersion, personResult.getSpecVersion());
		assertEquals(personName, personResult.getName().get());
		CreationInfo ci = personResult.getCreationInfo();
		assertEquals(created, ci.getCreated());
		assertEquals(specVersion, ci.getSpecVersion());
		assertEquals(1, ci.getCreatedBys().size());
		for (Agent createdBy:ci.getCreatedBys()) {
			assertEquals(inflated, createdBy);
		}
		List<String> verify = inflated.verify();
		assertTrue(verify.isEmpty());
	}
	
	
	@Test
	public void testDeserializeWithExternalElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDDeserializer deserializer = new JsonLDDeserializer(modelStore);
		
		String specVersion = "3.0.0";
		String created = "2024-07-18T12:00:00Z";
		String personSpdxId = "https://this/is/a/person";
		String packageSpdxId = "https://this/is/a/package";
		String packageName = "my package";
		
		ObjectNode creationInfoNode = mapper.createObjectNode();
		creationInfoNode.set("type", new TextNode("CreationInfo"));
		creationInfoNode.set("specVersion", new TextNode(specVersion));
		creationInfoNode.set("created", new TextNode(created));
		ArrayNode createdBysNode = mapper.createArrayNode();
		createdBysNode.add(new TextNode(personSpdxId));
		creationInfoNode.set("createdBy", createdBysNode);
		
		ObjectNode packageNode = mapper.createObjectNode();
		packageNode.set("spdxId", new TextNode(packageSpdxId));
		packageNode.set("type", new TextNode("software_Package"));
		packageNode.set("creationInfo", creationInfoNode);
		packageNode.set("name", new TextNode(packageName));
		
		TypedValue result = deserializer.deserializeElement(packageNode);
		assertEquals(specVersion, result.getSpecVersion());
		assertEquals(SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, result.getType());
		assertEquals(packageSpdxId, result.getObjectUri());
		
		CoreModelObject inflated = SpdxModelFactory.inflateModelObject(modelStore, packageSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, null, specVersion, false, "");
		assertTrue(inflated instanceof SpdxPackage);
		SpdxPackage packageResult = (SpdxPackage)inflated;
		assertEquals(specVersion, packageResult.getSpecVersion());
		assertEquals(packageName, packageResult.getName().get());
		CreationInfo ci = packageResult.getCreationInfo();
		assertEquals(created, ci.getCreated());
		assertEquals(specVersion, ci.getSpecVersion());
		assertEquals(1, ci.getCreatedBys().size());
		for (Agent createdBy:ci.getCreatedBys()) {
			assertEquals(personSpdxId, createdBy.getObjectUri());
		}
		List<String> verify = inflated.verify();
		assertTrue(verify.isEmpty());
	}

}
