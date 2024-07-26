/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.library.SpdxModelFactory;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.ExtendedSpdxStore;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * @author Gary O'Neall
 * 
 * Serializable store which reads and writes the SPDX Spec version 3 JSON LD format
 *
 */
public class JsonLDStore extends ExtendedSpdxStore
		implements
			ISerializableModelStore {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDStore.class);
	static final ObjectMapper JSON_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
	
	boolean pretty = true;
	
	/**
	 * @param baseStore underlying store to use
	 * @param pretty if true, use less compact prettier JSON LD format on output
	 */
	public JsonLDStore(IModelStore baseStore, boolean pretty) {
		super(baseStore);
		this.pretty = pretty;
	}
	
	/**
	 * @param baseStore underlying store to use
	 */
	public JsonLDStore(IModelStore baseStore) {
		this(baseStore, true);
	}
	
	/**
	 * @return if true, use less compact prettier JSON LD format on output
	 */
	public boolean getPretty() {
		return this.pretty;
	}
	
	/**
	 * @param pretty if true, use less compact prettier JSON LD format on output
	 */
	public void setPretty(boolean pretty) {
		this.pretty = pretty;
	}

	public void serialize(OutputStream stream)
			throws InvalidSPDXAnalysisException, IOException {
		JsonLDSerializer serializer;
		try {
			serializer = new JsonLDSerializer(JSON_MAPPER, pretty, SpdxModelFactory.getLatestSpecVersion(), this);
		} catch (GenerationException e) {
			throw new InvalidSPDXAnalysisException("Unable to reate JSON LD serializer", e);
		}
		JsonNode output = serializer.serialize();
		JsonGenerator jgen = null;
		try {
			jgen = JSON_MAPPER.getFactory().createGenerator(stream);
			if (pretty) {
				jgen.useDefaultPrettyPrinter();
			}
			JSON_MAPPER.writeTree(jgen, output);
		} finally {
		    if (Objects.nonNull(jgen)) {
		        jgen.close();
		    }
		}
	}

	public void deSerialize(InputStream stream, boolean overwrite)
			throws InvalidSPDXAnalysisException, IOException {
		Objects.requireNonNull(stream, "Input stream must not be null");
		JsonNode root = JSON_MAPPER.readTree(stream);
		if (!overwrite) {
			List<String> existingElementUris = getExistingElementUris(root);
			if (!existingElementUris.isEmpty()) {
				StringBuilder sb = new StringBuilder("The SPDX element IDs would be overwritten: ");
				sb.append(existingElementUris.get(0));
				int index = 1;
				while (index < 5 && index < existingElementUris.size()) {
					sb.append(", ");
					sb.append(existingElementUris.get(index++));
				}
				if (existingElementUris.size() >= 5) {
					sb.append(", [more]...");
				}
				throw new InvalidSPDXAnalysisException("The SPDX element IDs would be overwritten: ");
			}
		}
		JsonLDDeserializer deserializer = new JsonLDDeserializer(this);
		if (!root.isObject()) {
			throw new InvalidSPDXAnalysisException("Root of the JSON LD file is not an SPDX object");
		}
		JsonNode graph = root.get("@graph");
		if (Objects.nonNull(graph)) {
			deserializer.deserializeGraph(graph);
		} else {
			try {
				deserializer.deserializeElement(root);
			} catch (GenerationException e) {
				throw new InvalidSPDXAnalysisException("Error opening or reading SPDX 3.X schema",e);
			}
		}
	}

	/**
	 * @param root root of a graph containing SPDX elements
	 * @return a list of any SPDX Element URI's that already exist in the base model store
	 */
	private List<String> getExistingElementUris(JsonNode root) {
		List<String> retval = new ArrayList<>();
		JsonNode graph = root.get("@graph");
		if (Objects.nonNull(graph)) {
			if (graph.isArray()) {
				for (JsonNode spdxObject:((ArrayNode)graph)) {
					JsonNode spdxId = spdxObject.get("spdxId");
					if (Objects.nonNull(spdxId) && !isAnon(spdxId.asText()) && exists(spdxId.asText())) {
						retval.add(spdxId.asText());
					}
				}
			}
		} else {
			// single SPDX element
			JsonNode spdxId = root.get("spdxId");
			if (Objects.nonNull(spdxId) && !isAnon(spdxId.asText()) && exists(spdxId.asText())) {
				retval.add(spdxId.asText());
			}
		}
		return retval;
	}

}
