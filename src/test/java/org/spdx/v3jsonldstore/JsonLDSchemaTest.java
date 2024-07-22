/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import static org.junit.Assert.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Schema;

/**
 * @author gary
 *
 */
public class JsonLDSchemaTest {

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
}
