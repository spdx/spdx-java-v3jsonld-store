/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.core.Agent;
import org.spdx.library.model.v3_0_1.core.CreationInfo;
import org.spdx.library.model.v3_0_1.core.ExternalElement;
import org.spdx.library.model.v3_0_1.core.HashAlgorithm;
import org.spdx.library.model.v3_0_1.core.Person;
import org.spdx.library.model.v3_0_1.core.Relationship;
import org.spdx.library.model.v3_0_1.core.RelationshipType;
import org.spdx.library.model.v3_0_1.core.SpdxDocument;
import org.spdx.library.model.v3_0_1.security.CvssV3VulnAssessmentRelationship;
import org.spdx.library.model.v3_0_1.security.Vulnerability;
import org.spdx.library.model.v3_0_1.software.SpdxFile;
import org.spdx.library.model.v3_0_1.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * @author Gary O'Neall
 */
public class JsonLDSerializerTest {
	ObjectMapper mapper;
	IModelStore modelStore;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		SpdxModelFactory.init();
		mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
		modelStore = new InMemSpdxStore();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for serializing All Objects
	 * @throws GenerationException 
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerializeAllObjects() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);

		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(null);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		assertEquals(1, resultCreationInfos.size());
		JsonNode resultCreationInfo = resultCreationInfos.get(0);
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		String creationInfoId = resultCreationInfo.get("@id").asText();
		
		assertEquals(2, resultElements.size());
		JsonNode resultCreatedBy;
		JsonNode resultPkg;
		if (resultElements.get(0).get("type").asText().equals("Person")) {
			resultCreatedBy = resultElements.get(0);
			resultPkg = resultElements.get(1);
		} else {
			resultCreatedBy = resultElements.get(1);
			resultPkg = resultElements.get(0);
		}
		assertEquals(creationInfoId, resultCreatedBy.get("creationInfo").asText());
		assertEquals(agentUri, resultCreatedBy.get("spdxId").asText());
		assertEquals("Person", resultCreatedBy.get("type").asText());
		assertEquals(createdName, resultCreatedBy.get("name").asText());
		
		assertEquals(creationInfoId, resultPkg.get("creationInfo").asText());
		assertEquals(pkgUri, resultPkg.get("spdxId").asText());
		assertEquals(pkgName, resultPkg.get("name").asText());
		List<JsonNode> resultVerfiedUsings = new ArrayList<>();
		resultPkg.get("verifiedUsing").elements().forEachRemaining(node -> resultVerfiedUsings.add(node));
		assertEquals(1, resultVerfiedUsings.size());
		JsonNode resultHash = resultVerfiedUsings.get(0);
		assertTrue(resultHash.isObject());
		assertEquals("Hash", resultHash.get("type").asText());
		assertEquals(hashValue, resultHash.get("hashValue").asText());
		assertEquals(hashAlgorithm.getLongName(), resultHash.get("algorithm").asText());
		
		assertTrue(serializer.getSchema().validate(result));
	}
	
	/**
	 * Test method for get schema validation
	 * @throws GenerationException 
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerializeValidate() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);

		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		Agent createdBy = new Person(modelStore, agentUri, copyManager, true, prefix);
		createdBy.setName(createdName);

		
		CreationInfo creationInfo = createdBy.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		createdBy.setCreationInfo(creationInfo);
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(null);
		assertTrue(serializer.getSchema().validate(result));
	}
	
	@Test
	public void testSerializeSingleElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		
		JsonNode result = serializer.serialize(pkg);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		
		assertEquals(1, resultElements.size());
		JsonNode resultCreationInfo = resultElements.get(0).get("creationInfo");
		assertTrue(resultCreationInfos.isEmpty());
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		assertEquals(pkgUri, resultElements.get(0).get("spdxId").asText());
		assertEquals(pkgName, resultElements.get(0).get("name").asText());
		List<JsonNode> resultVerfiedUsings = new ArrayList<>();
		resultElements.get(0).get("verifiedUsing").elements().forEachRemaining(node -> resultVerfiedUsings.add(node));
		assertEquals(1, resultVerfiedUsings.size());
		JsonNode resultHash = resultVerfiedUsings.get(0);
		assertTrue(resultHash.isObject());
		assertEquals("Hash", resultHash.get("type").asText());
		assertEquals(hashValue, resultHash.get("hashValue").asText());
		assertEquals(hashAlgorithm.getLongName(), resultHash.get("algorithm").asText());
		
		assertTrue(serializer.getSchema().validate(result));
	}
	
	@Test
	public void testSerializeSpdxDocumentElement() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
		String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
		String fileName1 = "File";
		String fileUri1 = "https://my/unique/file1";
		String fileName2 = "secondFile";
		String fileUri2 = "https://my/unique/file2";
		String fileName3 = "thirdFile";
		String fileUri3 = "https://my/unique/file3";
		String externalElementUri = "http://external";
		String relationshipUri = "urn:this:is:relationship";
		String documentUri = "urn:my:document";
		String externalLocationHint = "https://location/is/here";
		
		ModelCopyManager copyManager = new ModelCopyManager();
		SpdxPackage pkg = new SpdxPackage(modelStore, pkgUri, copyManager, true, prefix);
		CreationInfo creationInfo = pkg.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = pkg.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		pkg.setCreationInfo(creationInfo);
		pkg.setName(pkgName);
		pkg.getVerifiedUsings().add(pkg.createHash(modelStore.getNextId(IdType.Anonymous))
				.setAlgorithm(hashAlgorithm)
				.setHashValue(hashValue)
				.build());
		SpdxFile file1 = pkg.createSpdxFile(fileUri1)
				.setName(fileName1)
				.build();
		SpdxFile file2 = pkg.createSpdxFile(fileUri2)
				.setName(fileName2)
				.build();
		@SuppressWarnings("unused")
		SpdxFile file3 = pkg.createSpdxFile(fileUri3)
				.setName(fileName3)
				.build();
		ExternalElement externalElement = new ExternalElement(externalElementUri);
		Relationship relationship = pkg.createRelationship(relationshipUri)
				.setFrom(pkg)
				.addTo(externalElement)
				.setRelationshipType(RelationshipType.CONTAINS)
				.build();
		
		SpdxDocument spdxDoc = pkg.createSpdxDocument(documentUri)
				.addSpdxImport(pkg.createExternalMap(modelStore.getNextId(IdType.Anonymous))
						.setExternalSpdxId(externalElementUri)
						.setLocationHint(externalLocationHint)
						.build())
				.addRootElement(pkg)
				.addRootElement(file2)
				.addElement(pkg)
				.addElement(file1)
				.addElement(relationship)
				.build();
		JsonNode result = serializer.serialize(spdxDoc);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultCreationInfos = new ArrayList<>();
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if ("CreationInfo".equals(type.asText())) {
				resultCreationInfos.add(element);
			} else {
				resultElements.add(element);
			}
		});
		assertEquals(1, resultCreationInfos.size());
		JsonNode resultCreationInfo = resultCreationInfos.get(0);
		assertEquals(createdDate, resultCreationInfo.get("created").asText());
		assertEquals(specVersion, resultCreationInfo.get("specVersion").asText());
		List<JsonNode> resultCreatedBys = new ArrayList<>();
		resultCreationInfo.get("createdBy").elements().forEachRemaining(element -> resultCreatedBys.add(element));
		assertEquals(1, resultCreatedBys.size());
		assertEquals(agentUri, resultCreatedBys.get(0).asText());
		String creationInfoId = resultCreationInfo.get("@id").asText();
		
		assertEquals(5, resultElements.size());
		JsonNode docResult = null;
		JsonNode relationshipResult = null;
		JsonNode file1Result = null;
		JsonNode file2Result = null;
		JsonNode file3Result = null;
		JsonNode resultPkg = null;
		JsonNode resultExternal = null;
		for (JsonNode elementResult:resultElements) {
			if (documentUri.equals(elementResult.get("spdxId").asText())) {
				docResult = elementResult;
			}
			if (relationshipUri.equals(elementResult.get("spdxId").asText())) {
				relationshipResult = elementResult;
			}
			if (fileUri1.equals(elementResult.get("spdxId").asText())) {
				file1Result = elementResult;
			}
			if (fileUri2.equals(elementResult.get("spdxId").asText())) {
				file2Result = elementResult;
			}
			if (pkgUri.equals(elementResult.get("spdxId").asText())) {
				resultPkg = elementResult;
			} if (fileUri3.equals(elementResult.get("spdxId").asText())) {
				file3Result = elementResult;
			} if (externalElementUri.equals(elementResult.get("spdxId").asText())) {
				resultExternal = elementResult;
			}
		}
		assertEquals(creationInfoId, resultPkg.get("creationInfo").asText());
		assertEquals(pkgName, resultPkg.get("name").asText());
		assertTrue(Objects.nonNull(docResult));
		assertTrue(Objects.nonNull(file2Result));
		assertEquals(fileName2, file2Result.get("name").asText());
		assertTrue(Objects.nonNull(file1Result));
		assertEquals(fileName1, file1Result.get("name").asText());
		assertTrue(Objects.isNull(file3Result));
		assertTrue(Objects.nonNull(relationshipResult));
		assertEquals(pkgUri, relationshipResult.get("from").asText());
		assertTrue(relationshipResult.get("to").isArray());
		assertEquals(1, relationshipResult.withArrayProperty("to").size());
		assertEquals(externalElementUri, relationshipResult.withArrayProperty("to").get(0).asText());
		assertEquals(RelationshipType.CONTAINS.getLongName(), relationshipResult.get("relationshipType").asText());
		assertTrue(Objects.isNull(resultExternal));
	}

	@Test
	public void testSerializeDouble() throws GenerationException, InvalidSPDXAnalysisException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, false, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		String prefix = "http://test.uri#";
		String pkgUri = prefix + "PACKAGE";
		String agentUri = prefix + "AGENT";
		String relUri = prefix + "REL";
		String vulnUri = prefix + "VULN";
		String createdName = "Creator";
		String createdDate = "2024-07-22T16:01:15Z";
		String specVersion = "3.0.0";
		String pkgName = "Package Name";
		double score = 4.3;

		ModelCopyManager copyManager = new ModelCopyManager();
		CvssV3VulnAssessmentRelationship rel = new CvssV3VulnAssessmentRelationship(modelStore, relUri, copyManager, true, prefix);
		CreationInfo creationInfo = rel.createCreationInfo(modelStore.getNextId(IdType.Anonymous))
				.setCreated(createdDate)
				.setSpecVersion(specVersion)
				.build();
		Agent createdBy = rel.createPerson(agentUri)
				.setCreationInfo(creationInfo)
				.setName(createdName)
				.build();
		creationInfo.getCreatedBys().add(createdBy);
		rel.setCreationInfo(creationInfo);
		rel.setRelationshipType(RelationshipType.HAS_ASSESSMENT_FOR);
		Vulnerability vuln = rel.createVulnerability(vulnUri).build();
		rel.setFrom(vuln);
		SpdxPackage pkg = rel.createSpdxPackage(pkgUri).setName(pkgName).build();
		rel.getTos().add(pkg);
		rel.setScore(score);
		rel.setVectorString("(AV:N/AC:M/Au:N/C:P/I:N/A:N)");

		JsonNode result = serializer.serialize(rel);
		assertTrue(result.isObject());
		JsonNode context = result.get("@context");
		assertTrue(context.asText().startsWith("https://spdx.org/rdf/3."));
		JsonNode graph = result.get("@graph");
		assertTrue(graph.isArray());
		List<JsonNode> resultElements = new ArrayList<>();
		graph.elements().forEachRemaining(element -> {
			JsonNode type = element.get("type");
			if (!"CreationInfo".equals(type.asText())) {
				resultElements.add(element);
			}
		});

		assertEquals(1, resultElements.size());
		assertEquals(relUri, resultElements.get(0).get("spdxId").asText());
		JsonNode scoreResult = resultElements.get(0).get("security_score");
		assertEquals(score, scoreResult.asDouble(), 0.00001);
	}
}
