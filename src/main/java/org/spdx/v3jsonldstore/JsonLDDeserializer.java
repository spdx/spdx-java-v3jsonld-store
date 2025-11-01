/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.SimpleUriValue;
import org.spdx.core.TypedValue;
import org.spdx.library.ListedLicenses;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.PropertyDescriptor;
import org.spdx.storage.listedlicense.SpdxListedLicenseModelStore;

import com.fasterxml.jackson.databind.JsonNode;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * Class to manage deserializing SPDX 3.X JSON-LD
 * 
 * @author Gary O'Neall
 */
public class JsonLDDeserializer {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDDeserializer.class);
	
	static final Set<String> ALL_SPDX_TYPES;
	static final Set<String> NON_PROPERTY_FIELD_NAMES;
	static final Map<String, String> JSON_PREFIX_TO_MODEL_PREFIX;

	static final String SPDX_ID_PROP = "spdxId";

	private static final String SPEC_VERSION_PROP = "specVersion";
	
	static {
		Set<String> allSpdxTypes = new HashSet<>();
		Map<String, String> jsonPrefixToModelPrefix = new HashMap<>();
		Arrays.spliterator(SpdxConstantsV3.ALL_SPDX_CLASSES).forEachRemaining(c -> {
			allSpdxTypes.add(c);
			String nmSpace = c.split("\\.")[0];
			jsonPrefixToModelPrefix.put(nmSpace.toLowerCase(), nmSpace);
		});
		ALL_SPDX_TYPES = Collections.unmodifiableSet(allSpdxTypes);
		JSON_PREFIX_TO_MODEL_PREFIX = Collections.unmodifiableMap(jsonPrefixToModelPrefix);
		
		Set<String> nonPropertyFieldNames = new HashSet<>();
		nonPropertyFieldNames.add("@id");
		nonPropertyFieldNames.add(SPDX_ID_PROP);
		nonPropertyFieldNames.add("type");
		NON_PROPERTY_FIELD_NAMES = Collections.unmodifiableSet(nonPropertyFieldNames);
	}
	
	private final IModelStore modelStore;
	private final ModelCopyManager copyManager;
	private final ConcurrentMap<String, String> jsonAnonToStoreAnon = new ConcurrentHashMap<>();
	private final ConcurrentMap<String, JsonLDSchema> versionToSchema = new ConcurrentHashMap<>();

	/**
	 * @param modelStore Model store to deserialize the JSON text into
	 */
	public JsonLDDeserializer(IModelStore modelStore) {
		this.modelStore = modelStore;
		this.copyManager = new ModelCopyManager();
	}

	/**
	 * Deserializes the JSON-LD graph into the modelStore
	 * @param graph Graph to deserialize
	 * @return list of non-anonymous typed value Elements found in the graph nodes
	 * @throws InvalidSPDXAnalysisException on SPDX parsing errors
	 */
	public List<TypedValue> deserializeGraph(JsonNode graph) throws InvalidSPDXAnalysisException {
		List<TypedValue> nonAnonGraphItems = new ArrayList<>();
		if (!graph.isArray()) {
			logger.error("Invalid type for deserializeGraph - must be an array");
			throw new InvalidSPDXAnalysisException("Invalid type for deserializeGraph - must be an array");
		}
		Map<String, String> creationInfoIdToSpecVersion = findCreationInfos(graph);
		
		// Second pass - create the top level objects in the graph
		Map<String, TypedValue> graphIdToTypedValue = new HashMap<>();
		for (Iterator<JsonNode> iter = graph.elements(); iter.hasNext(); ) {
			JsonNode graphNode = iter.next();
			String id = graphNode.has(SPDX_ID_PROP) ? graphNode.get(SPDX_ID_PROP).asText() : graphNode.get("@id").asText();
			if (Objects.nonNull(id)) {
				Optional<String> type = typeNodeToType(graphNode.get("type"));
				if (type.isPresent()) {
					// create the object so that it can be referenced during deserialization
					String specVersion = getSpecVersionFromNode(graphNode, creationInfoIdToSpecVersion, 
							SpdxModelFactory.getLatestSpecVersion());
					TypedValue tv = createTypedValueFromNode(id, type.get(), specVersion);
					modelStore.create(tv);
					graphIdToTypedValue.put(id, tv);
					if (!modelStore.isAnon(id)) {
						nonAnonGraphItems.add(tv);
					}
				}
			} else {
				logger.warn("Missing ID for one of the SPDX objects in the graph");
			}
		}
		
		// 3rd pass - deserialize the properties
		for (Iterator<JsonNode> iter = graph.elements(); iter.hasNext(); ) {
			try {
				deserializeCoreObject(iter.next(), SpdxModelFactory.getLatestSpecVersion(), 
						creationInfoIdToSpecVersion, graphIdToTypedValue);
			} catch (GenerationException e) {
				throw new InvalidSPDXAnalysisException("Unable to open schema file");
			}
		}
		return nonAnonGraphItems;
	}
	

	/**
	 * @param id from the JSON-LD file
	 * @param type SPDX type
	 * @param specVersion version of the spec
	 * @return a TypedValue based on the id, type, and specVersion
	 * @throws InvalidSPDXAnalysisException on model errors
	 */
	private TypedValue createTypedValueFromNode(String id, String type,
			String specVersion) throws InvalidSPDXAnalysisException {
		String storeId;
		if (id.startsWith("_:")) {
			if (!jsonAnonToStoreAnon.containsKey(id)) {
				jsonAnonToStoreAnon.put(id, modelStore.getNextId(IdType.Anonymous));
			}
			storeId = jsonAnonToStoreAnon.get(id);
		} else {
			storeId = id;
		}
		return new TypedValue(storeId, type, specVersion);
	}

	/**
	 * @param graph Graph of SPDX elements
	 * @return creationInfo JSON IDs and spec versions
	 */
	private Map<String, String> findCreationInfos(JsonNode graph) {
		Map<String, String> retval = new HashMap<>();
		for (Iterator<JsonNode> iter = graph.elements(); iter.hasNext(); ) {
			JsonNode graphNode = iter.next();
			Optional<String> type = typeNodeToType(graphNode.get("type"));
			if (type.isPresent() && SpdxConstantsV3.CORE_CREATION_INFO.equals(type.get())) {
				String id = graphNode.has(SPDX_ID_PROP) ? graphNode.get(SPDX_ID_PROP).asText() : graphNode.get("@id").asText();
				if (graphNode.has(SPEC_VERSION_PROP) && Objects.nonNull(id)) {
					retval.put(id, graphNode.get(SPEC_VERSION_PROP).asText());
				} else {
					logger.warn("Unable to obtain spec version for a creation info: {}", Objects.isNull(id) ? "[no ID]" : id);
				}
			}
		}
		return retval;
	}

	/**
	 * @param node SPDX object node
	 * @param creationInfoIdToSpecVersion map of creation info IDs to spec versions
	 * @param defaultSpecVersion default to use if no spec information could be found
	 * @return the spec version
	 */
	String getSpecVersionFromNode(JsonNode node, Map<String, String> creationInfoIdToSpecVersion, String defaultSpecVersion) {
		if (node.has(SPEC_VERSION_PROP)) {
			return node.get(SPEC_VERSION_PROP).asText();
		} else if (node.has("creationInfo")) {
			JsonNode creationInfoNode = node.get("creationInfo");
			if (creationInfoNode.isObject()) {
				if (creationInfoNode.has(SPEC_VERSION_PROP)) {
					return creationInfoNode.get(SPEC_VERSION_PROP).asText();
				} else {
					logger.warn("Missing creation info object spec version");
					return defaultSpecVersion;
				}
			} else {
				String creationInfoId = creationInfoNode.asText();
				if (creationInfoIdToSpecVersion.containsKey(creationInfoId)) {
					return creationInfoIdToSpecVersion.get(creationInfoId);
				} else {
					logger.warn("Missing creation info string spec version");
					return defaultSpecVersion;
				}
			}
		} else {
			return defaultSpecVersion;
		}
	}

	/**
	 * Deserialize a core object into the modelStore
	 * @param node Node containing an SPDX core object
	 * @param defaultSpecVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return TypedValue of the core object
	 * @throws InvalidSPDXAnalysisException on errors converting to SPDX
	 * @throws GenerationException on errors creating the schema
	 */
	private synchronized TypedValue deserializeCoreObject(JsonNode node, String defaultSpecVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		TypedValue tv = getOrCreateCoreObject(node, graphIdToTypedValue, defaultSpecVersion, creationInfoIdToSpecVersion);
		for (Iterator<Entry<String, JsonNode>> fields = node.fields(); fields.hasNext(); ) {
			Entry<String, JsonNode> field = fields.next();
			if (!NON_PROPERTY_FIELD_NAMES.contains(field.getKey())) {
				PropertyDescriptor property;
				try {
					Optional<PropertyDescriptor> optDesc = jsonFieldNameToProperty(field.getKey(), tv.getSpecVersion());
					if (optDesc.isEmpty()) {
						throw new InvalidSPDXAnalysisException("No property descriptor for field "+field.getKey());
					}
					property = optDesc.get();
				} catch (GenerationException e) {
					throw new InvalidSPDXAnalysisException("Unable to convert a JSON field name to a property", e);
				}
				if (field.getValue().isArray()) {
					for (Iterator<JsonNode> elements = field.getValue().elements(); elements.hasNext(); ) {
						modelStore.addValueToCollection(tv.getObjectUri(), property, toStoredObject(field.getKey(), elements.next(), tv.getSpecVersion(),
								creationInfoIdToSpecVersion, graphIdToTypedValue));
					}
				} else {
					modelStore.setValue(tv.getObjectUri(), property, toStoredObject(field.getKey(), field.getValue(), tv.getSpecVersion(), 
							creationInfoIdToSpecVersion, graphIdToTypedValue));
				}
			}
		}
		return tv;
	}


	/**
	 * Fetches the typed value for the core object from the map if exists, otherwise create, add to map
	 * @param node JSON Node for the core object
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @param defaultSpecVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @return existing or created TypedValue for the core object
	 * @throws InvalidSPDXAnalysisException on model exceptions
	 */
	private TypedValue getOrCreateCoreObject(JsonNode node,
			Map<String, TypedValue> graphIdToTypedValue, String defaultSpecVersion,
			Map<String, String> creationInfoIdToSpecVersion) throws InvalidSPDXAnalysisException {
		String jsonNodeId;
		if (node.has("@id")) {
			jsonNodeId = node.get("@id").asText();
		} else {
			jsonNodeId = node.has(SPDX_ID_PROP) ? node.get(SPDX_ID_PROP).asText() : null;
		}
		if (graphIdToTypedValue.containsKey(jsonNodeId)) {
			return graphIdToTypedValue.get(jsonNodeId);
		} else {
			// Need to create the object
			String id;
			Optional<String> type;
			String specVersion;
			if (Objects.isNull(jsonNodeId)) {
				id = modelStore.getNextId(IdType.Anonymous);
			} else if (jsonNodeId.startsWith("_:")) {
				if (!jsonAnonToStoreAnon.containsKey(jsonNodeId)) {
					jsonAnonToStoreAnon.put(jsonNodeId, modelStore.getNextId(IdType.Anonymous));
				}
				id = jsonAnonToStoreAnon.get(jsonNodeId);
			} else {
				id = jsonNodeId;
			}
			type = typeNodeToType(node.get("type"));
			if (type.isEmpty()) {
				logger.error("Missing type for core object {}", node);
				throw new InvalidSPDXAnalysisException("Missing type for core object " + node);
			}
			specVersion = getSpecVersionFromNode(node, creationInfoIdToSpecVersion, defaultSpecVersion);
			TypedValue tv = new TypedValue(id, type.get(), specVersion);
			modelStore.create(tv);
			graphIdToTypedValue.put(id, tv);
			return tv;
		}
	}

	/**
	 * @param propertyName the name of the property in the JSON schema
	 * @param value JSON node containing an object to store in the modelStore
	 * @param specVersion version of the spec to use if no creation information is available
	 * @param creationInfoIdToSpecVersion Map of creation info IDs to spec versions
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return an object suitable for storing in the model store
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors obtaining the schema
	 */
	private Object toStoredObject(String propertyName, JsonNode value, String specVersion,
			Map<String, String> creationInfoIdToSpecVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		Optional<String> propertyType = getOrCreateSchema(specVersion).getPropertyType(propertyName);
		switch (value.getNodeType()) {
			case ARRAY:
				throw new InvalidSPDXAnalysisException("Can not convert a JSON array to a stored object");
			case BOOLEAN: {
				if (propertyType.isEmpty() || JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
					return value.asBoolean();
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Boolean");
				}
			}
			case NULL: throw new InvalidSPDXAnalysisException("Can not convert a JSON NULL to a stored object");
			case NUMBER: {
				if (propertyType.isEmpty() || JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
					return value.asInt();
				} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
					return value.asDouble();
				} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
					return value.asText();
				} else {
					throw new InvalidSPDXAnalysisException("Type mismatch.  Expecting "+propertyType+" but was a JSON Boolean");
				}
			}
			case OBJECT: return deserializeCoreObject(value, specVersion, creationInfoIdToSpecVersion, graphIdToTypedValue);
			case STRING:
				return jsonStringToStoredValue(propertyName, value, specVersion, graphIdToTypedValue);
			case BINARY:
			case MISSING:
			case POJO:
			default: throw new InvalidSPDXAnalysisException("Unsupported JSON node type: "+ value);
			}
	}

	/**
	 * @param propertyName name of property in the JSON schema
	 * @param jsonValue string value
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return appropriate SPDX object based on the type associated with the propertyName
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on error getting JSON schemas
	 */
	private Object jsonStringToStoredValue(String propertyName, JsonNode jsonValue, String specVersion, 
			Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException, GenerationException {
		// A JSON string can represent an Element, another object (like CreatingInfo), an enumeration, an
		// individual value URL, an external URI
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		if (schema.isSpdxObject(propertyName)) {
			return jsonStringToSpdxObject(jsonValue, specVersion, graphIdToTypedValue);
		} else if (schema.isEnum(propertyName)) {
			// we can assume that the @vocab points to the prefix for the enumerations
			Optional<String> vocab = schema.getVocab(propertyName);
			if (vocab.isEmpty()) {
				throw new InvalidSPDXAnalysisException("Missing vocabulary for enum property "+propertyName);
			}
			return new SimpleUriValue(vocab.get() + jsonValue.asText());
		} else {
			Optional<String> propertyType = schema.getPropertyType(propertyName);
			if (propertyType.isEmpty()) {
				logger.warn("Missing property type for value {}.  Defaulting to a string type", jsonValue);
				return jsonValue.asText();
			} else if (JsonLDSchema.STRING_TYPES.contains(propertyType.get())) {
				return jsonValue.asText();
			} else if (JsonLDSchema.DOUBLE_TYPES.contains(propertyType.get())) {
				return Double.parseDouble(jsonValue.asText());
			} else if (JsonLDSchema.INTEGER_TYPES.contains(propertyType.get())) {
				return Integer.parseInt(jsonValue.asText());
			} else if (JsonLDSchema.BOOLEAN_TYPES.contains(propertyType.get())) {
				return Boolean.parseBoolean(jsonValue.asText());
			} else {
				throw new InvalidSPDXAnalysisException("Unknown type: "+propertyType.get()+" for property "+propertyName);
			}
		}
	}
	
	/**
	 * @param jsonValue string value
	 * @param specVersion version of the spec
	 * @param graphIdToTypedValue map of top level Object URIs and IDs stored in the graph
	 * @return SPDX object based on the type associated with the propertyName
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 */
	private Object jsonStringToSpdxObject(JsonNode jsonValue,
			String specVersion, Map<String, TypedValue> graphIdToTypedValue) throws InvalidSPDXAnalysisException {
		if (graphIdToTypedValue.containsKey(jsonValue.asText())) {
			return graphIdToTypedValue.get(jsonValue.asText());
		} else if (jsonValue.asText().startsWith(SpdxConstantsV3.SPDX_LISTED_LICENSE_NAMESPACE)) {
			String licenseOrExceptionId = SpdxListedLicenseModelStore.objectUriToLicenseOrExceptionId(jsonValue.asText());
			if (ListedLicenses.getListedLicenses().isSpdxListedLicenseId(licenseOrExceptionId) ||
					ListedLicenses.getListedLicenses().isSpdxListedExceptionId(licenseOrExceptionId)) {
				return copyManager.copy(modelStore, ListedLicenses.getListedLicenses().getLicenseModelStore(),
						jsonValue.asText(), specVersion, null);
			} else {
				// treat as an external element
				return new SimpleUriValue(jsonValue.asText());
			}
		} else if (!jsonValue.asText().startsWith("_:")) {
			// either an individual URI or an external element
			return new SimpleUriValue(jsonValue.asText());
		} else {
			throw new InvalidSPDXAnalysisException("Can not determine property type for "+jsonValue.asText());
		}
	}

	/**
	 * @param fieldName JSON name of the field
	 * @param specVersion version of the spec used for the JSON field name conversion
	 * @return Property descriptor associated with the JSON field name based on the Schema
	 * @throws GenerationException when we can not create a schema
	 */
	private Optional<PropertyDescriptor> jsonFieldNameToProperty(String fieldName,
																 String specVersion) throws GenerationException {
		JsonLDSchema schema = getOrCreateSchema(specVersion);
		Optional<PropertyDescriptor> retval = schema.getPropertyDescriptor(fieldName);
		if (retval.isPresent()) {
			return retval;
		}
		// we'll assume this is a URI for an extension property
		int lastPartIndex = fieldName.lastIndexOf('#');
		if (lastPartIndex < 0) {
			lastPartIndex = fieldName.lastIndexOf('/');
		}
		if (lastPartIndex < 0) {
			lastPartIndex = 0;
		}
		return Optional.of(new PropertyDescriptor(
				fieldName.substring(lastPartIndex+1), fieldName.substring(0, lastPartIndex+1)));

	}

	/**
	 * @param specVersion version of the spec
	 * @return a schema for the spec version supplied
	 * @throws GenerationException when we can not create a schema
	 */
	private JsonLDSchema getOrCreateSchema(String specVersion) throws GenerationException {
		JsonLDSchema schema = versionToSchema.get(specVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  specVersion),
					String.format("spdx-context-v%s.jsonld",  specVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			versionToSchema.put(specVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.warn("Unable to get a schema for spec version {}.  Trying latest spec version.", specVersion);
		}
		String latestVersion = SpdxModelFactory.getLatestSpecVersion();
		schema = versionToSchema.get(latestVersion);
		if (Objects.nonNull(schema)) {
			return schema;
		}
		try {
			schema = new JsonLDSchema(String.format("schema-v%s.json",  latestVersion),
					String.format("spdx-context-v%s.jsonld",  latestVersion),
					String.format("spdx-model-v%s.jsonld",  specVersion));
			versionToSchema.put(latestVersion, schema);
			return schema;
		} catch (GenerationException e) {
			logger.error("Unable to get JSON schema for latest version", e);
			throw e;
		}
	}

	/**
	 * @param typeNode node containing the type
	 * @return the SPDX type
	 */
	private Optional<String> typeNodeToType(JsonNode typeNode) {
		if (Objects.isNull(typeNode)) {
			return Optional.empty();
		}
		String jsonType = typeNode.asText();
		String retval;
		if (jsonType.contains("_")) {
			String[] typeParts = jsonType.split("_");
			String profile = JSON_PREFIX_TO_MODEL_PREFIX.get(JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(typeParts[0], typeParts[0]));
			if (Objects.isNull(profile)) {
				return Optional.empty();
			}
			retval = profile + "." + JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(typeParts[1], typeParts[1]);
		} else {
			retval = "Core." + JsonLDSchema.RESERVED_JAVA_WORDS.getOrDefault(jsonType, jsonType);
		}
		return ALL_SPDX_TYPES.contains(retval) ? Optional.of(retval) : Optional.empty();
	}

	/**
	 * Deserialize a single element into the modelStore
	 * @param elementNode element to deserialize
	 * @return the typedValue of the deserialized object
	 * @throws InvalidSPDXAnalysisException on invalid SPDX data
	 * @throws GenerationException on errors with the JSON schemas
	 */
	public TypedValue deserializeElement(JsonNode elementNode) throws GenerationException, InvalidSPDXAnalysisException {
		Map<String, TypedValue> mapIdToTypedValue = new HashMap<>();
		Map<String, String> creationInfoIdToSpecVersion = new HashMap<>();
		
		String id = elementNode.has(SPDX_ID_PROP) ? elementNode.get(SPDX_ID_PROP).asText() : elementNode.get("@id").asText();
		if (Objects.nonNull(id)) {
			if (id.startsWith("_:")) {
				throw new InvalidSPDXAnalysisException("Can not serialize an anonymous (blank) element");
			}
			Optional<String> type = typeNodeToType(elementNode.get("type"));
			if (type.isEmpty()) {
				throw new InvalidSPDXAnalysisException("Missing type for element "+id);
			}
			String specVersion = getSpecVersionFromNode(elementNode, creationInfoIdToSpecVersion, 
					SpdxModelFactory.getLatestSpecVersion());
			TypedValue tv = new TypedValue(id, type.get(), specVersion);
			modelStore.create(tv);
			mapIdToTypedValue.put(id, tv);
		}
		return deserializeCoreObject(elementNode, SpdxModelFactory.getLatestSpecVersion(), creationInfoIdToSpecVersion, mapIdToTypedValue);
	}

}
