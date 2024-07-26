/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
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
import org.spdx.library.model.v3.core.Element;
import org.spdx.library.model.v3.core.Person;
import org.spdx.library.model.v3.core.ProfileIdentifierType;
import org.spdx.library.model.v3.core.Relationship;
import org.spdx.library.model.v3.core.RelationshipType;
import org.spdx.library.model.v3.core.SpdxDocument;
import org.spdx.library.model.v3.software.Sbom;
import org.spdx.library.model.v3.software.SbomType;
import org.spdx.library.model.v3.software.SpdxFile;
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
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testDeserializeGraph() throws InvalidSPDXAnalysisException {
JsonLDDeserializer deserializer = new JsonLDDeserializer(modelStore);
		
		String specVersion = "3.0.0";
		String created = "2024-07-18T12:00:00Z";
		String personSpdxId = "https://this/is/a/person";
		String creationInfoId = "_:creationInfo1";
		String documentSpdxId = "https://this/is/a/document";
		String sbomSpdxId = "https://this/is/an/sbom";
		String packageSpdxId = "https://this/is/a/package";
		String fileSpdxId = "https://this/is/a/file";
		String relationshipSpdxId = "https://this/is/a/relationship";
		String personName = "My Name Is Gary";
		List<ProfileIdentifierType> conformances = Arrays.asList(new ProfileIdentifierType[] {
				ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE
		});
		List<String> conformancesStr = new ArrayList<>();
		conformances.forEach(con -> conformancesStr.add(con.getLongName()));
		List<SbomType> sbomTypes = Arrays.asList(new SbomType[] {SbomType.BUILD});
		List<String> sbomTypesStr = new ArrayList<>();
		sbomTypes.forEach(sbomType -> sbomTypesStr.add(sbomType.getLongName()));
		String packageName = "package name";
		String packageVersion = "2.2";
		String packageDownloadLocation = "https://github.com/some/donwnload";
		String packageBuiltTime = "2022-18-18T14:00:00Z";
		List<String> originated = Arrays.asList(new String[] {personSpdxId});
		String fileName = "/root/src/filename";
		String primaryPurpose = "executable";
		String fileCopyright = "copyright my company";
		String completeness = "complete";
		RelationshipType relationshipType = RelationshipType.CONTAINS;
		
		// creation info
		ObjectNode creationInfoNode = mapper.createObjectNode();
		creationInfoNode.set("type", new TextNode("CreationInfo"));
		creationInfoNode.set("specVersion", new TextNode(specVersion));
		creationInfoNode.set("created", new TextNode(created));
		creationInfoNode.set("@id", new TextNode(creationInfoId));
		ArrayNode createdBysNode = mapper.createArrayNode();
		createdBysNode.add(new TextNode(personSpdxId));
		creationInfoNode.set("createdBy", createdBysNode);
		ObjectNode personNode = mapper.createObjectNode();
		personNode.set("type", new TextNode("Person"));
		personNode.set("spdxId", new TextNode(personSpdxId));
		personNode.set("name", new TextNode(personName));
		personNode.set("creationInfo", new TextNode(creationInfoId));
		
		// Document
		ObjectNode documentNode = mapper.createObjectNode();
		documentNode.set("type", new TextNode("SpdxDocument"));
		documentNode.set("spdxId", new TextNode(documentSpdxId));
		documentNode.set("creationInfo", new TextNode(creationInfoId));
		ArrayNode rootElementsNode = mapper.createArrayNode();
		rootElementsNode.add(new TextNode(sbomSpdxId));
		documentNode.set("rootElement", rootElementsNode);
		ArrayNode profileConformanceNode = mapper.createArrayNode();
		conformancesStr.forEach(conformance -> profileConformanceNode.add(new TextNode(conformance)));
		documentNode.set("profileConformance", profileConformanceNode);
		
		// SBOM
		ObjectNode sbomNode = mapper.createObjectNode();
		sbomNode.set("type", new TextNode("software_Sbom"));
		sbomNode.set("spdxId", new TextNode(sbomSpdxId));
		sbomNode.set("creationInfo", new TextNode(creationInfoId));
		ArrayNode sbomRootNode = mapper.createArrayNode();
		sbomRootNode.add(new TextNode(packageSpdxId));
		sbomNode.set("rootElement", sbomRootNode);
		ArrayNode sbomTypesNode = mapper.createArrayNode();
		sbomTypesStr.forEach(sbomType -> sbomTypesNode.add(new TextNode(sbomType)));
		sbomNode.set("software_sbomType", sbomTypesNode);
		
		// Package
		ObjectNode packageNode = mapper.createObjectNode();
		packageNode.set("type", new TextNode("software_Package"));
		packageNode.set("spdxId", new TextNode(packageSpdxId));
		packageNode.set("creationInfo", new TextNode(creationInfoId));
		packageNode.set("name", new TextNode(packageName));
		packageNode.set("software_packageVersion", new TextNode(packageVersion));
		packageNode.set("software_downloadLocation", new TextNode(packageDownloadLocation));
		packageNode.set("builtTime", new TextNode(packageBuiltTime));
		ArrayNode originatedByNode = mapper.createArrayNode();
		originated.forEach(orig -> originatedByNode.add(new TextNode(orig)));
		packageNode.set("originatedBy", originatedByNode);
		
		
		// File
		ObjectNode fileNode = mapper.createObjectNode();
		fileNode.set("type", new TextNode("software_File"));
		fileNode.set("spdxId", new TextNode(fileSpdxId));
		fileNode.set("creationInfo", new TextNode(creationInfoId));
		fileNode.set("name", new TextNode(fileName));
		fileNode.set("software_primaryPurpose", new TextNode(primaryPurpose));
		fileNode.set("software_copyrightText", new TextNode(fileCopyright));
		
		// Relationship
		ObjectNode relationshipNode = mapper.createObjectNode();
		relationshipNode.set("type", new TextNode("Relationship"));
		relationshipNode.set("spdxId", new TextNode(relationshipSpdxId));
		relationshipNode.set("creationInfo", new TextNode(creationInfoId));
		relationshipNode.set("from", new TextNode(packageSpdxId));
		relationshipNode.set("relationshipType", new TextNode(relationshipType.getLongName()));
		ArrayNode toNode = mapper.createArrayNode();
		toNode.add(new TextNode(fileSpdxId));
		relationshipNode.set("to", toNode);
		relationshipNode.set("completeness", new TextNode(completeness));
		
		ArrayNode graphNode = mapper.createArrayNode();
		graphNode.add(creationInfoNode);
		graphNode.add(personNode);
		graphNode.add(documentNode);
		graphNode.add(sbomNode);
		graphNode.add(packageNode);
		graphNode.add(fileNode);
		graphNode.add(relationshipNode);
		
		deserializer.deserializeGraph(graphNode);
		
		Person personResult = (Person)SpdxModelFactory.inflateModelObject(modelStore, personSpdxId, SpdxConstantsV3.CORE_PERSON, null, specVersion, false, "");
		assertEquals(specVersion, personResult.getSpecVersion());
		assertEquals(personName, personResult.getName().get());
		CreationInfo ci = personResult.getCreationInfo();
		assertEquals(created, ci.getCreated());
		assertEquals(specVersion, ci.getSpecVersion());
		assertEquals(1, ci.getCreatedBys().size());
		for (Agent createdBy:ci.getCreatedBys()) {
			assertEquals(personResult, createdBy);
		}
		List<String> verify = personResult.verify();
		assertTrue(verify.isEmpty());
		
		SpdxDocument documentResult = (SpdxDocument)SpdxModelFactory.inflateModelObject(modelStore, documentSpdxId, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, specVersion, false, "");
		assertEquals(1, documentResult.getRootElements().size());
		assertEquals(sbomSpdxId, documentResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
		assertEquals(conformancesStr.size(), documentResult.getProfileConformances().size());
		assertTrue(documentResult.getProfileConformances().containsAll(conformances));
		
		Sbom sbomResult = (Sbom)SpdxModelFactory.inflateModelObject(modelStore, sbomSpdxId, SpdxConstantsV3.SOFTWARE_SBOM, null, specVersion, false, "");
		assertEquals(1, sbomResult.getRootElements().size());
		assertEquals(packageSpdxId, sbomResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
		assertEquals(sbomTypes.size(), sbomResult.getSbomTypes().size());
		assertTrue(sbomResult.getSbomTypes().containsAll(sbomTypes));
		
		SpdxPackage packageResult = (SpdxPackage)SpdxModelFactory.inflateModelObject(modelStore, packageSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, null, specVersion, false, "");
		assertEquals(packageName, packageResult.getName().get());
		assertEquals(packageVersion, packageResult.getPackageVersion().get());
		assertEquals(packageDownloadLocation, packageResult.getDownloadLocation().get());
		assertEquals(packageBuiltTime, packageResult.getBuiltTime().get());
		assertEquals(originated.size(), packageResult.getOriginatedBys().size());
		packageResult.getOriginatedBys().forEach(agent -> assertTrue(originated.contains(agent.getObjectUri())));
		
		SpdxFile fileResult = (SpdxFile)SpdxModelFactory.inflateModelObject(modelStore, fileSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_FILE, null, specVersion, false, "");
		assertEquals(fileName, fileResult.getName().get());
		assertEquals(primaryPurpose, fileResult.getPrimaryPurpose().get().getLongName());
		assertEquals(fileCopyright, fileResult.getCopyrightText().get());
		
		Relationship relationshipResult = (Relationship)SpdxModelFactory.inflateModelObject(modelStore, relationshipSpdxId, SpdxConstantsV3.CORE_RELATIONSHIP, null, specVersion, false, "");
		assertEquals(packageSpdxId, relationshipResult.getFrom().getObjectUri());
		assertEquals(1, relationshipResult.getTos().size());
		assertEquals(fileSpdxId, relationshipResult.getTos().toArray(new Element[1])[0].getObjectUri());
		assertEquals(relationshipType, relationshipResult.getRelationshipType());
		assertEquals(completeness, relationshipResult.getCompleteness().get().getLongName());
		
		List<String> verifyResult = documentResult.verify();
		assertTrue(verifyResult.isEmpty());
	}

	@Test
	public void testDeserializeMultipleCreationInfos() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDDeserializer deserializer = new JsonLDDeserializer(modelStore);
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
