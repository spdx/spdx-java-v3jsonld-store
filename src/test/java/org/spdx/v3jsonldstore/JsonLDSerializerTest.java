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
import org.spdx.library.SpdxModelFactory;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * @author gary
 *
 */
public class JsonLDSerializerTest {
	ObjectMapper mapper;
	IModelStore modelStore;

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
		mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
		modelStore = new InMemSpdxStore();
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}
	
	@Test
	public void testGetAllAnyLicenseInfos() throws GenerationException {
		JsonLDSerializer serializer = new JsonLDSerializer(mapper, true, SpdxModelFactory.getLatestSpecVersion(), modelStore);
		List<String> retval = serializer.getAnyLicenseInfoTypes();
		assertFalse(retval.isEmpty());
		assertTrue(retval.contains("simplelicensing_AnyLicenseInfo"));
		assertTrue(retval.contains("expandedlicensing_ConjunctiveLicenseSet"));
		assertTrue(retval.contains("simplelicensing_LicenseExpression"));
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDSerializer#JsonLDSerializer(com.fasterxml.jackson.databind.ObjectMapper, boolean, java.lang.String, org.spdx.storage.IModelStore)}.
	 */
	@Test
	public void testJsonLDSerializer() {
		fail("Not yet implemented");
	}

	/**
	 * Test method for {@link org.spdx.v3jsonldstore.JsonLDSerializer#serialize()}.
	 */
	@Test
	public void testSerialize() {
		fail("Not yet implemented");
	}

}
