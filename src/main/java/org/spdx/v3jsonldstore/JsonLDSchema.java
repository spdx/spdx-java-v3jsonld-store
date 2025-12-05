/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.storage.PropertyDescriptor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Optional;
import java.util.Set;

import net.jimblackler.jsonschemafriend.GenerationException;
import net.jimblackler.jsonschemafriend.Schema;
import net.jimblackler.jsonschemafriend.SchemaException;
import net.jimblackler.jsonschemafriend.SchemaStore;
import net.jimblackler.jsonschemafriend.Validator;

/**
 * Represents the JSON Schema for SPDX 3.X includes a number of convenience methods
 *
 * @author Gary O'Neall
 */
@SuppressWarnings("LoggingSimilarMessage")
public class JsonLDSchema {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDSchema.class);
	private static final String ANY_CLASS_URI_SUFFIX = "/$defs/AnyClass";
	
	public static final Map<String, String> RESERVED_JAVA_WORDS = new HashMap<>();
	public static final Map<String, String> REVERSE_JAVA_WORDS = new HashMap<>();
	public static final Set<String> BOOLEAN_TYPES = new HashSet<>();
	public static final Set<String> INTEGER_TYPES = new HashSet<>();
	public static final Set<String> DOUBLE_TYPES = new HashSet<>();
	public static final Set<String> STRING_TYPES = new HashSet<>();
	static {
		RESERVED_JAVA_WORDS.put("Package", "SpdxPackage");
		REVERSE_JAVA_WORDS.put("SpdxPackage", "Package");
		RESERVED_JAVA_WORDS.put("package", "spdxPackage");
		REVERSE_JAVA_WORDS.put("spdxPackage", "package");
		RESERVED_JAVA_WORDS.put("File", "SpdxFile");
		REVERSE_JAVA_WORDS.put("SpdxFile", "File");
		RESERVED_JAVA_WORDS.put("file", "spdxFile");
		REVERSE_JAVA_WORDS.put("spdxFile", "file");
		RESERVED_JAVA_WORDS.put("import", "spdxImport");
		REVERSE_JAVA_WORDS.put("spdxImport", "import");
		BOOLEAN_TYPES.add("http://www.w3.org/2001/XMLSchema#boolean");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#integer");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#nonPositiveInteger");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#nonNegativeInteger");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#positiveInteger");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#negativeInteger");
		INTEGER_TYPES.add("http://www.w3.org/2001/XMLSchema#long");
		DOUBLE_TYPES.add("http://www.w3.org/2001/XMLSchema#decimal");
		DOUBLE_TYPES.add("http://www.w3.org/2001/XMLSchema#float");
		DOUBLE_TYPES.add("http://www.w3.org/2001/XMLSchema#double");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#duration");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#dateType");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#dateTimeStamp");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#time");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#date");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#string");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#normalizedString");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#token");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#language");
		STRING_TYPES.add("http://www.w3.org/2001/XMLSchema#anyURI");
	}
	
	static final ObjectMapper JSON_MAPPER = new ObjectMapper();
	private static final String OBJECT_TYPE = "http://www.w3.org/2002/07/owl#ObjectProperty";
	private static final String INDIVIDUAL_TYPE = "http://www.w3.org/2002/07/owl#NamedIndividual";
	private final JsonNode contexts;
	private final Schema spdxRootSchema;
	private final Map<String, JsonNode> modelStatements = new HashMap<>(); // maps the ID to the statement
	private final Validator validator = new Validator();
	private final List<String> elementTypes;
	private final List<String> anyLicenseInfoTypes;

	/**
	 * @param schemaFileName File name for the schema file in the resources directory
	 * @param contextFileName File name for the context file in the resources directory
	 * @param modelFileName File name for the model file in the resources directory
	 * @throws GenerationException on schema loading error
	 */
	public JsonLDSchema(String schemaFileName, String contextFileName, String modelFileName) throws GenerationException {
		SchemaStore schemaStore = new SchemaStore();
		spdxRootSchema = schemaStore.loadSchema(JsonLDSchema.class.getResourceAsStream("/resources/"+schemaFileName));
		try (InputStream is = JsonLDSchema.class.getResourceAsStream("/resources/"+contextFileName)) {
			if (Objects.isNull(is)) {
				throw new GenerationException("Unable to open JSON LD context file");
			}
			JsonNode root = JSON_MAPPER.readTree(is);
			this.contexts = root.get("@context");
			if (Objects.isNull(contexts)) {
				throw new GenerationException("Missing contexts");
			}
			if (!contexts.isObject()) {
				throw new GenerationException("Contexts is not an object");
			}
		} catch (IOException e1) {
			throw new GenerationException("I/O Error loading JSON LD Context file", e1);
		}
		try (InputStream is = JsonLDSchema.class.getResourceAsStream("/resources/"+modelFileName)) {
			if (Objects.isNull(is)) {
				throw new GenerationException("Unable to open JSON LD model file");
			}
			JsonNode root = JSON_MAPPER.readTree(is);
			for (Iterator<JsonNode> iter = root.elements(); iter.hasNext(); ) {
				JsonNode modelStatement = iter.next();
				if (modelStatement.has("@id")) {
					modelStatements.put(modelStatement.get("@id").asText(), modelStatement);
				}
			}
		} catch (IOException e1) {
			throw new GenerationException("I/O Error loading JSON LD model file", e1);
		}
		elementTypes = collectTypes("Element");
		anyLicenseInfoTypes = collectTypes("simplelicensing_AnyLicenseInfo");
	}
	
	/**
	 * @return a list of all element types that are subclasses of superClass
	 */
	private List<String> collectTypes(String superClass) {
		List<String> retval = new ArrayList<>();
		for (Schema classSchema:getAllClasses()) {
			try {
				if (isSubclassOf(superClass, classSchema)) {
					Optional<URI> typeUri = getTypeUri(classSchema);
					if (typeUri.isPresent()) {
						retval.add(classUriToType(typeUri.get()));
					} else {
						logger.warn("No class type found for {}", classSchema.getUri());
					}
				}
			} catch (URISyntaxException e) {
				throw new RuntimeException("Unexpected URI syntax error", e);
			}
		}
		return retval;
	}

	/**
	 * @param classUri URI for the class
	 * @return type name used in the SPDX 3 model
	 */
	private String classUriToType(URI classUri) {
		String strClassUri = classUri.toString();
		String nameSpace = strClassUri.substring(0, classUri.toString().lastIndexOf('/'));
		String profile = nameSpace.substring(nameSpace.lastIndexOf('/') + 1);
		profile = RESERVED_JAVA_WORDS.getOrDefault(profile, profile);
		String className = strClassUri.substring(strClassUri.lastIndexOf('/') + 1);
		className = RESERVED_JAVA_WORDS.getOrDefault(className, className);
		return profile + "." + className;
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
		Schema thenSchema = subClass.getThen();
		Collection<Schema> allOfSchemas;
		if (Objects.nonNull(thenSchema)) {
			allOfSchemas = thenSchema.getAllOf();
		} else {
			allOfSchemas = subClass.getAllOf();
		}
		for (Schema allOfSchema:allOfSchemas) {
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
		return hasProperty(propertyName, schema, new HashSet<>());
	}
	
	/**
	 * @param propertyName name of the property to check
	 * @param schema schema containing property restrictions
	 * @param checkedSchemas set of schemas which has already been checked
	 * @return true if the schema requires a property named propertyName via properties, subSchemas, or allOf
	 */
	private boolean hasProperty(String propertyName, Schema schema, Set<Schema> checkedSchemas) {
		if (checkedSchemas.contains(schema)) {
			return false;
		}
		checkedSchemas.add(schema);
		if (schema.getProperties().containsKey(propertyName)) {
			return true;
		}
		for (Schema subSchema:schema.getSubSchemas().values()) {
			if (hasProperty(propertyName, subSchema, checkedSchemas)) {
				return true;
			}
		}
		for (Schema allOfSchema:schema.getAllOf()) {
			if (hasProperty(propertyName, allOfSchema, checkedSchemas)) {
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
				logger.warn("No context entry for {}", type.get());
				return Optional.empty();
			}
			if (!typeUriNode.isTextual()) {
				logger.warn("Wrong context type for {}", type.get());
				return Optional.empty();
			}
			try {
				URI retval = new URI(typeUriNode.asText());
				return Optional.of(retval);
			} catch (URISyntaxException e) {
				logger.warn("Invalid URI string in context file for {}", type.get());
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
        Schema ifSchema = classSchema.getIf();
        if (Objects.isNull(ifSchema)) {
            return getTypeFromOldSchema(classSchema);
        }
		Map<String, Schema> properties = ifSchema.getProperties();
		if (Objects.isNull(properties)) {
			logger.warn("No properties for {}", classSchema.getUri());
			return Optional.empty();
		}
		if (properties.containsKey("type")) {
			Schema typeSchema = properties.get("type");
			Object typeString = typeSchema.getConst();
			if (Objects.nonNull(typeString)) {
				if (typeString instanceof String) {
					return Optional.of((String)typeString);
				} else {
					logger.warn("Type string is not of type string {}", classSchema.getUri());
					return Optional.empty();
				}
			}
		}
		return Optional.empty();
	}

    /**
     * Gets the type from schemas prior to version3.0.1 where allOf is used to constrain the schema type
     * @param classSchema Schema for the class
     * @return JSON Schema type name for the class
     */
    private Optional<String> getTypeFromOldSchema(Schema classSchema) {
        Collection<Schema> allOfs = classSchema.getAllOf();
        if (Objects.isNull(allOfs)) {
            logger.warn("No allOfs for {}", classSchema.getUri());
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
            logger.warn("No OneOf for class schema type property {}", classSchema.getUri());
            return Optional.empty();
        }
        if (oneOf.size() > 1) {
            logger.warn("Too many OneOfs for class schema type property {}", classSchema.getUri());
            return Optional.empty();
        }
        for (Schema oneOfSchema:oneOf) {
            Object typeString = oneOfSchema.getConst();
            if (Objects.isNull(typeString)) {
                logger.warn("Type string is null {}", classSchema.getUri());
                return Optional.empty();
            }
            if (typeString instanceof String) {
                return Optional.of((String)typeString);
            } else {
                logger.warn("Type string is not of type string {}", classSchema.getUri());
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /**
	 * @param root Root JSON node of the JSON representation of an SPDX serialization
	 * @return true if the JSON node is valid
	 */
	public boolean validate(JsonNode root) {
		try {
			validator.validate(spdxRootSchema, JSON_MAPPER.treeToValue(root, Map.class));
			return true;
		} catch (SchemaException e) {
		      logger.error("JSON object does not match schema: {}", e.getMessage());
		      return false;
	    } catch (JsonProcessingException e) {
	    	logger.error("Unable to parse JSON object: {}", e.getMessage());
		      return false;
		} catch (IllegalArgumentException e) {
			logger.error(e.getMessage());
		      return false;
		}
	}

	/**
	 * @param spdxJsonFile file containing SPDX JSON LD content
	 * @return true if the JSON in file is valid according to the schema
	 * @throws IOException on file IO errors
	 */
	public boolean validate(File spdxJsonFile) throws IOException {
		try {
			validator.validate(spdxRootSchema, spdxJsonFile);
			return true;
		} catch (SchemaException e) {
		      logger.error("JSON object does not match schema: {}", e.getMessage());
		      return false;
	    } catch (JsonProcessingException e) {
	    	logger.error("Unable to parse JSON object: {}", e.getMessage());
		      return false;
		} catch (IllegalArgumentException e) {
			logger.error(e.getMessage());
		      return false;
		}
	}

	/**
	 * @return the elementTypes
	 */
	public List<String> getElementTypes() {
		return elementTypes;
	}

	/**
	 * @return the anyLicenseInfoTypes
	 */
	public List<String> getAnyLicenseInfoTypes() {
		return anyLicenseInfoTypes;
	}

	/**
	 * @param propertyName name of the property
	 * @return the JSON property type if it exists in the JSON-LD context
	 */
	public Optional<String> getPropertyType(String propertyName) {
		JsonNode propertyNode = contexts.get(propertyName);
		if (Objects.isNull(propertyNode)) {
			return Optional.empty();
		}
		JsonNode typeNode = propertyNode.get("@type");
		return Objects.isNull(typeNode) ? Optional.empty() : Optional.of(typeNode.asText());
	}

	/**
	 * @param propertyName name of a property in the JSON LD schema
	 * @return the vocab definition
	 */
	public Optional<String> getVocab(String propertyName) {
		JsonNode propertyNode = contexts.get(propertyName);
		if (Objects.isNull(propertyNode)) {
			return Optional.empty();
		}
		JsonNode contextNode = propertyNode.get("@context");
		if (Objects.isNull(contextNode)) {
			return Optional.empty();
		}
		JsonNode vocabNode = contextNode.get("@vocab");
		return Objects.isNull(vocabNode) ? Optional.empty() : Optional.of(vocabNode.asText());
	}

	/**
	 * @param fieldName name of a JSON field / property
	 * @return the SPDX model property descriptor for the JSON property
	 */
	public Optional<PropertyDescriptor> getPropertyDescriptor(String fieldName) {
		String propName = REVERSE_JAVA_WORDS.getOrDefault(fieldName, fieldName);
		JsonNode propertyNode = contexts.get(propName);
		if (Objects.isNull(propertyNode)) {
			return Optional.empty();
		}
		JsonNode idNode = propertyNode.get("@id");
		if (Objects.isNull(idNode)) {
			return Optional.empty();
		}
		String propertyUri = idNode.asText();
		String namespace = propertyUri.substring(0, propertyUri.lastIndexOf('/')+1);
		String name = propertyUri.substring(propertyUri.lastIndexOf('/')+1);
		return Optional.of(new PropertyDescriptor(name, namespace));
	}
	
	/**
	 * @param propertyName property name
	 * @return the SHACL statement from the model if it exists
	 */
	private Optional<JsonNode> getPropertyShacl(String propertyName) {
		JsonNode propertyNode = contexts.get(propertyName);
		if (Objects.isNull(propertyNode)) {
			return Optional.empty();
		}
		JsonNode idNode = propertyNode.get("@id");
		if (Objects.isNull(idNode)) {
			return Optional.empty();
		}
		return Optional.ofNullable(modelStatements.get(idNode.asText()));
	}

	/**
	 * @param propertyName Name of the property
	 * @return true if the value associated with the property is an ID representing an SPDX Object
	 */
	public boolean isSpdxObject(String propertyName) {
		if (isEnum(propertyName)) {
			return false;
		}
		Optional<JsonNode> shacl = getPropertyShacl(propertyName);
		if (shacl.isEmpty()) {
			return false;
		}
		boolean objectType = false;
		JsonNode types = shacl.get().get("@type");
		if (Objects.isNull(types)) {
			return false;
		}
        for (JsonNode type : types) {
            if (OBJECT_TYPE.equals(type.asText())) {
                objectType = true;
            }
        }
		return objectType;
	}
	
	/**
	 * @param propertyName Name of the property
	 * @param propertyValue property value
	 * @return true if the propertyValue represents an Individual from the vocabulary
	 */
	public boolean isIndividual(String propertyName, String propertyValue) {
		if (!isSpdxObject(propertyName)) {
			return false;
		}
		String id;
		JsonNode context = contexts.get(propertyValue);
		if (Objects.nonNull(context) && context.has("@id")) {
			id = context.get("@id").asText();
		} else {
			id = propertyValue;
		}
		JsonNode shacl = modelStatements.get(id);
		if (Objects.isNull(shacl)) {
			return false;
		}
		JsonNode types = shacl.get("@type");
		for (Iterator<JsonNode> iter = types.elements(); iter.hasNext(); ) {
			if (INDIVIDUAL_TYPE.equals(iter.next().asText())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param propertyName Name of the property
	 * @return true if the propertyValue represents an enumeration
	 */
	public boolean isEnum(String propertyName) {
		Optional<String> type = getPropertyType(propertyName);
		if (type.isEmpty()) {
			return false;
		}
		if (!"@vocab".equals(type.get())) {
			return false;
		}
		Optional<String> vocab = getVocab(propertyName);
		return vocab.isPresent() && !vocab.get().endsWith("terms/Core/Element/");
	}
}
