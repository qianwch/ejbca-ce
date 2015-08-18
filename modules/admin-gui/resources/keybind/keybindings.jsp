   				<h:outputText value="#{web.text.INTERNALKEYBINDING_ACTION}"/>
   			</f:facet>
			<h:commandButton rendered="#{guiInfo.status ne 'INTERNALKEYBINDING_STATUS_DISABLED'}" action="#{internalKeyBindingMBean.commandDisable}"
				value="#{web.text.INTERNALKEYBINDING_DISABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DISABLE_FULL}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.status eq 'INTERNALKEYBINDING_STATUS_DISABLED'}" action="#{internalKeyBindingMBean.commandEnable}"
				value="#{web.text.INTERNALKEYBINDING_ENABLE_SHORT}" title="#{web.text.INTERNALKEYBINDING_ENABLE_FULL}" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandDelete}"
				value="#{web.text.INTERNALKEYBINDING_DELETE_SHORT}" title="#{web.text.INTERNALKEYBINDING_DELETE_FULL}"
				onclick="return confirm('#{web.text.INTERNALKEYBINDING_CONF_DELETE}')" disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{!guiInfo.nextKeyAliasAvailable and guiInfo.cryptoTokenAvailable}"
				action="#{internalKeyBindingMBean.commandGenerateNewKey}"
				value="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_SHORT}" title="#{web.text.INTERNALKEYBINDING_GENERATENEWKEY_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.cryptoTokenAvailable}" action="#{internalKeyBindingMBean.commandGenerateRequest}"
				value="#{web.text.INTERNALKEYBINDING_GETCSR_SHORT}" title="#{web.text.INTERNALKEYBINDING_GETCSR_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton action="#{internalKeyBindingMBean.commandReloadCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RELOADCERTIFICATE_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
			<h:commandButton rendered="#{guiInfo.issuedByInternalCa}" action="#{internalKeyBindingMBean.commandRenewCertificate}"
				value="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_SHORT}" title="#{web.text.INTERNALKEYBINDING_RENEWCERTIFICATE_FULL}"
				disabled="#{internalKeyBindingMBean.forbiddenToEdit}"/>
		</h:column>
	</h:dataTable>
	<br/>
	<h:outputLink
		value="adminweb/keybind/keybinding.jsf?internalKeyBindingId=0&type=#{internalKeyBindingMBean.selectedInternalKeyBindingType}" rendered="#{internalKeyBindingMBean.allowedToEdit}">
		<h:outputText value="#{web.text.INTERNALKEYBINDING_CREATENEW}"/>
	</h:outputLink>
	</h:form>
	<h:form id="uploadCertificate" enctype="multipart/form-data" rendered="#{not empty internalKeyBindingMBean.uploadTargets and internalKeyBindingMBean.allowedToEdit}">
		<h3><h:outputText value="#{web.text.INTERNALKEYBINDING_UPLOADHEADER}"/></h3>
		<h:panelGrid columns="5">
			<h:outputLabel for="certificateUploadTarget" value="#{web.text.INTERNALKEYBINDING_UPLOAD_TARGET} #{internalKeyBindingMBean.selectedInternalKeyBindingType}:"/>
