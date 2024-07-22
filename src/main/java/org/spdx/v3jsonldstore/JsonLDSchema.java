/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.v3jsonldstore;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Optional;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Schema;
import net.jimblackler.jsonschemafriend.SchemaStore;

/**
 * @author Gary O'Neall
 * 
 * Represents the JSON Schema for SPDX 3.X includes a number of convenience methods
 *
 */
public class JsonLDSchema {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDSchema.class);
	private static final String ANY_CLASS_URI_SUFFIX = "/$defs/AnyClass";
	static final ObjectMapper JSON_MAPPER = new ObjectMapper();
	private JsonNode contexts;
	private Schema spdxRootSchema;

	/**
	 * @param schemaFileName File name for the schema file in the resources directory
	 * @throws GenerationException on schema loading error
	 */
	public JsonLDSchema(String schemaFileName, String contextFileName) throws GenerationException {
		SchemaStore schemaStore = new SchemaStore();
		spdxRootSchema = schemaStore.loadSchema(JsonLDSchema.class.getResourceAsStream("/resources/"+schemaFileName));
		try (InputStream is = JsonLDSchema.class.getResourceAsStream("/resources/"+contextFileName)) {
			if (Objects.isNull(is)) {
				throw new RuntimeException("Unable to open JSON LD context file");
			}
			JsonNode root;
			try {
				root = JSON_MAPPER.readTree(is);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			JsonNode contexts = root.get("@context");
			if (Objects.isNull(contexts)) {
				throw new GenerationException("Missing contexts");
			}
			if (!contexts.isObject()) {
				throw new GenerationException("Contexts is not an object");
			}
			this.contexts = contexts;
		} catch (IOException e1) {
			throw new GenerationException("I/O Error loading JSON LD Context file", e1);
		}
	}
	
	/**
	 * @return a list of schemas for all classes defined in the SPDX schema
	 */
	public Collection<Schema> getAllClasses() {
		for (Entry<URI, Schema> entry:spdxRootSchema.getSubSchemas().entrySet()) {
			if (entry.getKey().toString().endsWith(ANY_CLASS_URI_SUFFIX)) {
				return entry.getValue().getAnyOf();
			}
		}
		return Collections.emptyList();
	}
	
	/**
	 * @param superClassType superclass type
	 * @param subClass schema for the subclass
	 * @return true if the subClass schema contains the property restrictions for the superclass types
	 * @throws URISyntaxException on a bad superClassType string
	 */
	public boolean isSubclassOf(String superClassType, Schema subClass) throws URISyntaxException {
		URI superClassPropertyUri = new URI("#/$defs/" + superClassType + "_props");
		for (Schema allOfSchema:subClass.getAllOf()) {
			if (superClassPropertyUri.equals(allOfSchema.getUri())) {
				return true;
			}
			if (Objects.nonNull(allOfSchema.getUri()) && allOfSchema.getUri().toString().endsWith("_props") &&
					isSubclassOf(superClassType, allOfSchema)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * @param propertyName name of the property to check
	 * @param schema schema containing property restrictions
	 * @return true if the schema requires a property named propertyName via properties, subSchemas, or allOf
	 */
	public boolean hasProperty(String propertyName, Schema schema) {
		if (schema.getProperties().containsKey(propertyName)) {
			return true;
		}
		for (Schema subSchema:schema.getSubSchemas().values()) {
			if (hasProperty(propertyName, subSchema)) {
				return true;
			}
		}
		for (Schema allOfSchema:schema.getAllOf()) {
			if (hasProperty(propertyName, allOfSchema)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param className name of the class
	 * @return schema for the class if it exists
	 */
	public Optional<Schema> getClassSchema(String className) {
		for (Entry<URI, Schema> entry:spdxRootSchema.getSubSchemas().entrySet()) {
			if (entry.getKey().toString().endsWith("/$defs/"+className)) {
				return Optional.of(entry.getValue());
			}
		}
		return Optional.empty();
	}

	/**
	 * @param classSchema schema for a class
	 * @return type URI for the type of the class from the JSON LD Context
	 */
	public Optional<URI> getTypeUri(Schema classSchema) {
		Optional<String> type = getType(classSchema);
		if (type.isPresent()) {
			JsonNode typeUriNode = contexts.get(type.get());
			if (Objects.isNull(typeUriNode)) {
				logger.warn("No context entry for "+type.get());
				return Optional.empty();
			}
			if (!typeUriNode.isTextual()) {
				logger.warn("Wrong context type for "+type.get());
				return Optional.empty();
			}
			try {
				URI retval = new URI(typeUriNode.asText());
				return Optional.of(retval);
			} catch (URISyntaxException e) {
				logger.warn("Invalid URI string in context file for "+type.get());
				return Optional.empty();
			}
		} else {
			return Optional.empty();
		}
	}

	/**
	 * @param classSchema Schema for the class
	 * @return JSON Schema type name for the class
	 */
	public Optional<String> getType(Schema classSchema) {
		Collection<Schema> allOfs = classSchema.getAllOf();
		if (Objects.isNull(allOfs)) {
			logger.warn("No allOfs for " + classSchema.getUri());
			return Optional.empty();
		}
		Schema typeProperty = null;
		for (Schema allOfSchema:allOfs) {
			Map<String, Schema> properties = allOfSchema.getProperties();
			typeProperty = properties.get("type");
			if (Objects.nonNull(typeProperty)) {
				break;
			}
		}
		if (Objects.isNull(typeProperty)) {
			return Optional.empty();
		}
		Collection<Schema> oneOf = typeProperty.getOneOf();
		if (Objects.isNull(oneOf) || oneOf.isEmpty()) {
			logger.warn("No OneOf for class schema type property " + classSchema.getUri());
			return Optional.empty();
		}
		if (oneOf.size() > 1) {
			logger.warn("Too many OneOfs for class schema type property" + classSchema.getUri());
			return Optional.empty();
		}
		for (Schema oneOfSchema:oneOf) {
			Object typeString = oneOfSchema.getConst();
			if (Objects.isNull(typeString)) {
				logger.warn("Type string is null "+classSchema.getUri());
				return Optional.empty();
			}
			if (!(typeString instanceof String)) {
				logger.warn("Type string is not of type string " + classSchema.getUri());
				return Optional.empty();
			}
			return Optional.of((String)typeString);
		}
		return Optional.empty();
	}
}
