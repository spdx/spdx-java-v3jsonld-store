/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.library.model.v3_0_0.SpdxConstantsV3;
import org.spdx.storage.PropertyDescriptor;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Schema;

/**
 * @author gary
 *
 */
public class JsonLDSchemaTest {
	
	static final String JSON_EXAMPLE_FILE = "TestFiles" + File.separator + "package_sbom.json";

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDSchema#getAllClasses()}.
	 * @throws GenerationException 
	 */
	@Test
	public void testGetAllClasses() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Collection<Schema> result = schema.getAllClasses();
		assertTrue(result.size() > 0);
	}
	
	@Test
	public void testHasProperty() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Schema relationshipSchema = schema.getClassSchema("Relationship").get();
		assertTrue(schema.hasProperty("spdxId", relationshipSchema));
	}
	
	@Test
	public void testIsSubclassOf() throws GenerationException, URISyntaxException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Schema relationshipSchema = schema.getClassSchema("Relationship").get();
		assertTrue(schema.isSubclassOf("Element", relationshipSchema));
		assertFalse(schema.isSubclassOf("simplelicensing_AnyLicenseInfo", relationshipSchema));
	}

	@Test
	public void testGetTypeUri() throws GenerationException, URISyntaxException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Schema relationshipSchema = schema.getClassSchema("Relationship").get();
		assertEquals(new URI("https://spdx.org/rdf/3.0.0/terms/Core/Relationship"),
				schema.getTypeUri(relationshipSchema).get());
	}
	
	@Test
	public void testGetType() throws GenerationException, URISyntaxException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Schema relationshipSchema = schema.getClassSchema("Relationship").get();
		assertEquals("Relationship", schema.getType(relationshipSchema).get());
	}
	
	@Test
	public void testValidateFile() throws GenerationException, IOException {
		File exampleFile = new File(JSON_EXAMPLE_FILE);
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		assertTrue(schema.validate(exampleFile));
	}
	
	@Test
	public void testGetAllAnyLicenseInfos() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		List<String> retval = schema.getAnyLicenseInfoTypes();
		assertFalse(retval.isEmpty());
		assertTrue(retval.contains("SimpleLicensing.AnyLicenseInfo"));
		assertTrue(retval.contains("ExpandedLicensing.ConjunctiveLicenseSet"));
		assertTrue(retval.contains("SimpleLicensing.LicenseExpression"));
		assertFalse(retval.contains("Core.Relationship"));
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDSerializer#JsonLDSerializer(com.fasterxml.jackson.databind.ObjectMapper, boolean, java.lang.String, org.spdx.storage.IModelStore)}.
	 * @throws GenerationException 
	 */
	@Test
	public void testGetAllElements() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		List<String> retval = schema.getElementTypes();
		assertFalse(retval.isEmpty());
		assertTrue(retval.contains("SimpleLicensing.AnyLicenseInfo"));
		assertTrue(retval.contains("Core.Element"));
		assertTrue(retval.contains("Core.Relationship"));
		assertFalse(retval.contains("Core.CreationInfo"));
	}
	
	@Test
	public void testGetPropertyType() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Optional<String> result = schema.getPropertyType("element");
		assertTrue(result.isPresent());
		assertEquals("@id", result.get());
		result = schema.getPropertyType("endTime");
		assertTrue(result.isPresent());
		assertEquals("http://www.w3.org/2001/XMLSchema#dateTimeStamp", result.get());
	}
	
	@Test
	public void testGetVocab() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Optional<String> result = schema.getVocab("annotationType");
		assertTrue(result.isPresent());
		assertEquals("https://spdx.org/rdf/3.0.0/terms/Core/AnnotationType/", result.get());
	}
	
	@Test
	public void testGetPropertyDescriptor() throws GenerationException {
		JsonLDSchema schema = new JsonLDSchema("schema-v3.0.0.json", "spdx-context-v3.0.0.jsonld");
		Optional<PropertyDescriptor> result = schema.getPropertyDescriptor("beginIntegerRange");
		assertTrue(result.isPresent());
		assertEquals(SpdxConstantsV3.PROP_BEGIN_INTEGER_RANGE, result.get());
	}
}
