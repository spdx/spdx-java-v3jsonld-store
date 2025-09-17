/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedValue;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.library.model.v3_0_1.core.Agent;
import org.spdx.library.model.v3_0_1.core.CreationInfo;
import org.spdx.library.model.v3_0_1.core.Element;
import org.spdx.library.model.v3_0_1.core.HashAlgorithm;
import org.spdx.library.model.v3_0_1.core.ProfileIdentifierType;
import org.spdx.library.model.v3_0_1.core.Relationship;
import org.spdx.library.model.v3_0_1.core.RelationshipType;
import org.spdx.library.model.v3_0_1.core.SpdxDocument;
import org.spdx.library.model.v3_0_1.software.Sbom;
import org.spdx.library.model.v3_0_1.software.SbomType;
import org.spdx.library.model.v3_0_1.software.SpdxFile;
import org.spdx.library.model.v3_0_1.software.SpdxPackage;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * @author Gary O'Neall
 */
public class JsonLDStoreTest {
	
	private static final String PACKAGE_SBOM_FILE = "TestFiles/package_sbom.json";
	private static final String NO_DOCUMENT_FILE = "TestFiles/no_document.json";
	IModelStore innerStore;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		innerStore = new InMemSpdxStore();
		SpdxModelFactory.init();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * @throws Exception 
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#JsonLDStore(org.spdx.storage.IModelStore, boolean)}.
	 * @throws  
	 */
	@Test
	public void testJsonLDStoreIModelStoreBoolean() throws Exception {
		try (JsonLDStore ldStore = new JsonLDStore(innerStore, false)) {
			assertFalse(ldStore.getPretty());
		}
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#serialize(java.io.OutputStream)}.
	 * @throws InvalidSPDXAnalysisException 
	 */
	@Test
	public void testSerialize() throws Exception {
		
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			String prefix = "http://test.uri#";
			String pkgUri = prefix + "PACKAGE";
			String agentUri = prefix + "AGENT";
			String createdName = "Creator";
			String createdDate = "2024-07-22T16:01:15Z";
			String specVersion = "3.0.1";
			String pkgName = "Package Name";
			HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
			String hashValue = "d301fcd0b7c84c879456eb041af246fbc7edbfea54f6470a859d8bd4073a47b8";
			
			ModelCopyManager copyManager = new ModelCopyManager();
			SpdxPackage pkg = new SpdxPackage(ldStore, pkgUri, copyManager, true, prefix);
			CreationInfo creationInfo = new CreationInfo(ldStore, ldStore.getNextId(IdType.Anonymous),
					copyManager, true, prefix);
			creationInfo.setCreated(createdDate)
					.setSpecVersion(specVersion);
			Agent createdBy = creationInfo.createPerson(agentUri)
					.setCreationInfo(creationInfo)
					.setName(createdName)
					.build();
			creationInfo.getCreatedBys().add(createdBy);
			pkg.setCreationInfo(creationInfo);
			pkg.setName(pkgName);
			pkg.getVerifiedUsings().add(pkg.createHash(ldStore.getNextId(IdType.Anonymous))
					.setAlgorithm(hashAlgorithm)
					.setHashValue(hashValue)
					.build());
			
			String result;
			try (ByteArrayOutputStream bas = new ByteArrayOutputStream()) {
				ldStore.serialize(bas);
				result = bas.toString();
			}
			
			ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
			JsonNode root = mapper.readTree(result);
			JsonLDSchema jsonLDSchema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			assertTrue(jsonLDSchema.validate(root));
		}
	}
	
	@Test
	public void testValidateTestFile() throws Exception {
		String specVersion = "3.0.1";
		try (FileInputStream fis = new FileInputStream(new File(PACKAGE_SBOM_FILE))) {
			ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
			JsonNode root = mapper.readTree(fis);
			JsonLDSchema jsonLDSchema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			assertTrue(jsonLDSchema.validate(root));
		}
		
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDStore#deSerialize(java.io.InputStream, boolean)}.
	 * @throws Exception 
	 */
	@Test
	public void testDeSerialize() throws Exception {
		
		String specVersion = "3.0.1";
		String created = "2024-03-06T00:00:00Z";
		String personSpdxId = "http://spdx.example.com/Agent/JoshuaWatt";
		String documentSpdxId = "http://spdx.example.com/Document1";
		String sbomSpdxId = "http://spdx.example.com/BOM1";
		String packageSpdxId = "http://spdx.example.com/Package1";
		String fileSpdxId = "http://spdx.example.com/Package1/myprogram";
		String relationshipSpdxId = "http://spdx.example.com/Relationship/1";
		String personName = "Joshua Watt";
		List<ProfileIdentifierType> conformances = Arrays.asList(new ProfileIdentifierType[] {
				ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE
		});
		List<String> conformancesStr = new ArrayList<>();
		conformances.forEach(con -> conformancesStr.add(con.getLongName()));
		List<SbomType> sbomTypes = Arrays.asList(new SbomType[] {SbomType.BUILD});
		List<String> sbomTypesStr = new ArrayList<>();
		sbomTypes.forEach(sbomType -> sbomTypesStr.add(sbomType.getLongName()));
		String packageName = "my-package";
		String packageVersion = "1.0";
		String packageDownloadLocation = "http://dl.example.com/my-package_1.0.0.tar";
		String packageBuiltTime = "2024-03-06T00:00:00Z";
		List<String> originated = Arrays.asList(new String[] {personSpdxId});
		String fileName = "myprogram";
		String primaryPurpose = "executable";
		String fileCopyright = "Copyright 2024, Joshua Watt";
		String completeness = "complete";
		RelationshipType relationshipType = RelationshipType.CONTAINS;
		
		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (FileInputStream fis = new FileInputStream(new File(PACKAGE_SBOM_FILE))) {
				ldStore.deSerialize(fis, false);
			}
			
			SpdxDocument documentResult = (SpdxDocument)SpdxModelFactory.inflateModelObject(ldStore, documentSpdxId, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, specVersion, false, "");
			assertEquals(1, documentResult.getRootElements().size());
			assertEquals(sbomSpdxId, documentResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
			assertEquals(conformancesStr.size(), documentResult.getProfileConformances().size());
			assertTrue(documentResult.getProfileConformances().containsAll(conformances));
			assertEquals(created, documentResult.getCreationInfo().getCreated());
			assertEquals(personName, documentResult.getCreationInfo().getCreatedBys().toArray(new Agent[documentResult.getCreationInfo().getCreatedBys().size()])[0].getName().get());
			
			Sbom sbomResult = (Sbom)SpdxModelFactory.inflateModelObject(ldStore, sbomSpdxId, SpdxConstantsV3.SOFTWARE_SBOM, null, specVersion, false, "");
			assertEquals(1, sbomResult.getRootElements().size());
			assertEquals(packageSpdxId, sbomResult.getRootElements().toArray(new Element[1])[0].getObjectUri());
			assertEquals(sbomTypes.size(), sbomResult.getSbomTypes().size());
			assertTrue(sbomResult.getSbomTypes().containsAll(sbomTypes));
			
			SpdxPackage packageResult = (SpdxPackage)SpdxModelFactory.inflateModelObject(ldStore, packageSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_PACKAGE, null, specVersion, false, "");
			assertEquals(packageName, packageResult.getName().get());
			assertEquals(packageVersion, packageResult.getPackageVersion().get());
			assertEquals(packageDownloadLocation, packageResult.getDownloadLocation().get());
			assertEquals(packageBuiltTime, packageResult.getBuiltTime().get());
			assertEquals(originated.size(), packageResult.getOriginatedBys().size());
			packageResult.getOriginatedBys().forEach(agent -> assertTrue(originated.contains(agent.getObjectUri())));
			
			SpdxFile fileResult = (SpdxFile)SpdxModelFactory.inflateModelObject(ldStore, fileSpdxId, SpdxConstantsV3.SOFTWARE_SPDX_FILE, null, specVersion, false, "");
			assertEquals(fileName, fileResult.getName().get());
			assertEquals(primaryPurpose, fileResult.getPrimaryPurpose().get().getLongName());
			assertEquals(fileCopyright, fileResult.getCopyrightText().get());
			
			Relationship relationshipResult = (Relationship)SpdxModelFactory.inflateModelObject(ldStore, relationshipSpdxId, SpdxConstantsV3.CORE_RELATIONSHIP, null, specVersion, false, "");
			assertEquals(packageSpdxId, relationshipResult.getFrom().getObjectUri());
			assertEquals(1, relationshipResult.getTos().size());
			assertEquals(fileSpdxId, relationshipResult.getTos().toArray(new Element[1])[0].getObjectUri());
			assertEquals(relationshipType, relationshipResult.getRelationshipType());
			assertEquals(completeness, relationshipResult.getCompleteness().get().getLongName());
			
			List<String> verifyResult = documentResult.verify();
			assertTrue(verifyResult.isEmpty());
			
			try (FileInputStream fis = new FileInputStream(new File(PACKAGE_SBOM_FILE))) {
				try {
					ldStore.deSerialize(fis, false);
					fail("No overwrite should faild here");
				} catch (InvalidSPDXAnalysisException ex) {
					//expected
				}
			}
		}
	}

	/**
	 * Test deserializing a file wihtout an SPDX document
	 * @throws Exception on error
	 */
	@Test
	public void testDeserializeNoSpdxDocument() throws Exception {

		try (JsonLDStore ldStore = new JsonLDStore(innerStore)) {
			try (FileInputStream fis = new FileInputStream(new File(NO_DOCUMENT_FILE))) {
				ldStore.deSerialize(fis, false);
			}
			//noinspection unchecked
			List<SpdxDocument> docs =
					(List<SpdxDocument>) SpdxModelFactory.getSpdxObjects(ldStore, null, SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, null)
							.collect(Collectors.toList());
			assertEquals(1, docs.size());
			SpdxDocument doc = docs.get(0);
			assertEquals(2, doc.getElements().size());
			List<String> verify = doc.verify();
			assertTrue(verify.isEmpty());
		}
	}
}
