<%@ taglib uri="http://java.sun.com/jsf/html" prefix="h" %>
<%@ taglib uri="http://java.sun.com/jsf/core" prefix="f" %>

	<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOENDUSER_HELP}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendUserNotification" value="#{editService.notifyingType.useEndUserNotifications}"
			                         onchange="checkUseEndUserNotification()"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckEndUserSubjectTextField" value="#{editService.notifyingType.endUserSubject}" size="45" title="#{web.text.FORMAT_STRING}" />
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ENDUSERMESSAGE}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.ENDUSERMESSAGE_HELP}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckEndUserMessageTextArea" value="#{editService.notifyingType.endUserMessage}" rows="8" cols="45" />
	</h:panelGroup>

	<h:panelGroup>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN}"/><f:verbatim><br/></f:verbatim>
		<h:outputText value="#{web.text.SENDNOTIFICATIONTOADMIN_HELP}"/>
	</h:panelGroup>
	<h:panelGroup>				
			<h:selectBooleanCheckbox id="certCheckSendAdminNotification" value="#{editService.notifyingType.useAdminNotifications}"
			                         onchange="checkUseAdminNotification()"/>
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINSUBJECT}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputText id="certCheckAdminSubjectTextField" value="#{editService.notifyingType.adminSubject}" size="45" title="#{web.text.FORMAT_STRING}" />
	</h:panelGroup>	

	<h:panelGroup>
		<h:outputText value="#{web.text.ADMINMESSAGE}"/><f:verbatim><br/></f:verbatim>
	    <h:outputText value="#{web.text.ADMINMESSAGE_HELP}"/>
	</h:panelGroup>
	<h:panelGroup>				
		<h:inputTextarea id="certCheckAdminMessageTextArea" value="#{editService.notifyingType.adminMessage}" rows="8" cols="45" />
			<f:verbatim>
<script type="text/javascript">
<!--  
checkUseAdminNotification();
checkUseEndUserNotification();
-->
</script></f:verbatim>
	</h:panelGroup>

