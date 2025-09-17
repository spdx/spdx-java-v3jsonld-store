/**
 * SPDX-FileCopyrightText: Copyright (c) 2024 Source Auditor Inc.
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.v3jsonldstore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.core.CoreModelObject;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.TypedValue;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.SpdxConstantsV3;
import org.spdx.library.model.v3_0_1.SpdxModelClassFactoryV3;
import org.spdx.library.model.v3_0_1.core.*;
import org.spdx.storage.IModelStore;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.PropertyDescriptor;
import org.spdx.storage.simple.ExtendedSpdxStore;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import net.jimblackler.jsonschemafriend.GenerationException;

/**
 * Serializable store which reads and writes the SPDX Spec version 3 JSON LD format
 *
 * @author Gary O'Neall
 */
public class JsonLDStore extends ExtendedSpdxStore
		implements
			ISerializableModelStore {
	
	static final Logger logger = LoggerFactory.getLogger(JsonLDStore.class);
	static final ObjectMapper JSON_MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
	
	@SuppressWarnings("UnusedAssignment")
    boolean pretty = true;
	private boolean useExternalListedElements = false;
	
	/**
	 * Constructs a JsonLDStore with the specified base store and pretty format
	 * option
	 *
	 * @param baseStore underlying store to use
	 * @param pretty    if true, use less compact prettier JSON LD format on output
	 */
	public JsonLDStore(IModelStore baseStore, boolean pretty) {
		super(baseStore);
		this.pretty = pretty;
	}

	/**
	 * Constructs a JsonLDStore with the specified base store
	 *
	 * @param baseStore underlying store to use
	 */
	public JsonLDStore(IModelStore baseStore) {
		this(baseStore, true);
	}

	/**
	 * Check the pretty format option for JSON LD output
	 *
	 * @return if true, use less compact prettier JSON LD format on output
	 */
	public boolean getPretty() {
		return this.pretty;
	}

	/**
	 * Sets the pretty format option for JSON LD output
	 *
	 * @param pretty if true, use less compact prettier JSON LD format on output
	 */
	public void setPretty(boolean pretty) {
		this.pretty = pretty;
	}

	@Override
	public void serialize(OutputStream stream)
			throws InvalidSPDXAnalysisException, IOException {
		serialize(stream, null);
	}

	@Override 
	public void serialize(OutputStream stream, @Nullable CoreModelObject objectToSerialize)
			throws InvalidSPDXAnalysisException, IOException {
		JsonLDSerializer serializer;
		try {
			serializer = new JsonLDSerializer(JSON_MAPPER, pretty, useExternalListedElements, SpdxModelFactory.getLatestSpecVersion(), this);
		} catch (GenerationException e) {
			throw new InvalidSPDXAnalysisException("Unable to create JSON LD serializer", e);
		}
		JsonNode output = serializer.serialize(objectToSerialize);
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

	@Override
	public SpdxDocument deSerialize(InputStream stream, boolean overwrite)
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
				throw new InvalidSPDXAnalysisException("The SPDX element IDs would be overwritten: " + sb);
			}
		}
		JsonLDDeserializer deserializer = new JsonLDDeserializer(this);
		if (!root.isObject()) {
			throw new InvalidSPDXAnalysisException("Root of the JSON LD file is not an SPDX object");
		}
		JsonNode graph = root.get("@graph");
		if (Objects.nonNull(graph)) {
			List<TypedValue> graphElements = deserializer.deserializeGraph(graph);
			return elementsToSpdxDocument(graphElements);
		} else {
			try {
				TypedValue element = deserializer.deserializeElement(root);
				return elementsToSpdxDocument(Collections.singletonList(element));
			} catch (GenerationException e) {
				throw new InvalidSPDXAnalysisException("Error opening or reading SPDX 3.X schema",e);
			}
		}
	}


	/**
	 * Converts a list of elements from a serialized graph into an SPDX document
	 *
	 * @param graphElements elements found in the serialized graph
	 * @return an SPDX document representing the serialization
	 * @throws InvalidSPDXAnalysisException on SPDX parsing errors
	 */
	private SpdxDocument elementsToSpdxDocument(List<TypedValue> graphElements) throws InvalidSPDXAnalysisException {
		List<TypedValue> existingSpdxDocument = new ArrayList<>();
		graphElements.forEach(tv -> {
			if (SpdxConstantsV3.CORE_SPDX_DOCUMENT.equals(tv.getType())) {
				existingSpdxDocument.add(tv);
			}
		});
		SpdxDocument retval;
		if (existingSpdxDocument.size() == 1) {
			retval = (SpdxDocument)SpdxModelFactory.inflateModelObject(this, existingSpdxDocument.get(0).getObjectUri(),
						SpdxConstantsV3.CORE_SPDX_DOCUMENT, null, existingSpdxDocument.get(0).getSpecVersion(),
						 false, null); 
		} else {
			String prefix = "urn:generated-spdx-document:" + UUID.randomUUID();
			CreationInfo creationInfo = SpdxModelClassFactoryV3.createCreationInfo(
					this, prefix + ":Agent", "SPDX JSON-LD Deserializer",
					null);
			creationInfo.setComment("Document created while deserializing a JSON-LD file with no Document element meta-data");
			retval = creationInfo.createSpdxDocument(prefix + ":spdx-document").build();
		}
		Collection<Element> elements = retval.getElements();
		elements.clear();
		Collection<Element> roots = retval.getRootElements();
		boolean addAllToRoot = roots.isEmpty();
		Set<String> referencedExternalElementUris = new HashSet<>();
		Set<String> alreadySearched = new HashSet<>();
		for (TypedValue element:graphElements) {
			if (!retval.getObjectUri().equals(element.getObjectUri())) {
				CoreModelObject mo = SpdxModelFactory.inflateModelObject(this, element.getObjectUri(),
						element.getType(), null, element.getSpecVersion(), false, null);
				if (mo instanceof Element) {
					elements.add((Element)mo);
					if (addAllToRoot) {
						roots.add((Element)mo);
					}
					addExternalElements(mo, referencedExternalElementUris, alreadySearched);
				} else if (!(mo instanceof CreationInfo)) {
					// CreationInfos are allowed in the Serialization as a shortcut, but should not be included
					// in the elements.  Note that they are already deserialized and included as properties for
					// the elements as part of JsonLDDeserializer.deSerializeGraph
                    logger.warn("Non element in the serialized graph - {} will not be included in the SPDX document elements", element.getObjectUri());
				}
			}
		}
		Collection<ExternalMap> imports = retval.getSpdxImports();
		for (String externalUri:referencedExternalElementUris) {
			imports.add(retval.createExternalMap(getNextId(IdType.Anonymous))
					.setExternalSpdxId(externalUri)
					.build());
		}
		return retval;
	}

	/**
	 * Searches for any external elements referenced in the model object and adds
	 * that to the referencedExternalElementUris
	 *
	 * @param modelObject modelObject to search for external references
	 * @param referencedExternalElementUris referenced external element URIs
	 * @param alreadySearched set of URIs which have already been searched
	 * @throws InvalidSPDXAnalysisException on error fetching property values
	 */
	private void addExternalElements(CoreModelObject modelObject,
			Set<String> referencedExternalElementUris,
			Set<String> alreadySearched) throws InvalidSPDXAnalysisException {
		if (alreadySearched.contains(modelObject.getObjectUri())) {
			return;
		}
		alreadySearched.add(modelObject.getObjectUri());
		for (PropertyDescriptor pd:modelObject.getPropertyValueDescriptors()) {
			Optional<Object> value = modelObject.getObjectPropertyValue(pd);
			if (value.isPresent()) {
				if (value.get() instanceof ExternalElement) {
					referencedExternalElementUris.add(((ExternalElement)value.get()).getIndividualURI());
				} else if (value.get() instanceof CoreModelObject) {
					addExternalElements((CoreModelObject)value.get(), referencedExternalElementUris, alreadySearched);
				}
			}
		}
	}

	/**
	 * Retrieves the URIs of any SPDX elements that already exist in the base model
	 * store
	 *
	 * @param root root of a graph containing SPDX elements
	 * @return a list of any SPDX Element URI's that already exist in the base model
	 *         store
	 */
	private List<String> getExistingElementUris(JsonNode root) {
		List<String> retval = new ArrayList<>();
		JsonNode graph = root.get("@graph");
		if (Objects.nonNull(graph)) {
			if (graph.isArray()) {
				for (JsonNode spdxObject: graph) {
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

	/**
	 * Sets whether to use external listed elements
	 *
	 * @param useExternalListedElements if true, don't serialize any listed licenses
	 *                                  or exceptions - treat them as external
	 */
	public void setUseExternalListedElements(boolean useExternalListedElements) {
		this.useExternalListedElements  = useExternalListedElements;
	}

}
