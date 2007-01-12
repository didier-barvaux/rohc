<?xml version="1.0" encoding="ISO-8859-15"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

	<xsl:output method="xml" encoding="ISO-8859-15" indent="yes"/>

	<xsl:template match="test/startuplog">
	</xsl:template>

	<xsl:template match="test/packet">
		<xsl:apply-templates select="compression"/>
	</xsl:template>

	<xsl:template match="compression">
		<xsl:if test="status != 'ok'">
			<div>
				<h4>Compression of packet #<xsl:value-of select="../@id"/> failed:</h4>
				<p><pre><xsl:value-of select="log"/></pre></p>
			</div>
		</xsl:if>
	</xsl:template>

	<xsl:template match="test/summary">
	</xsl:template>

	<xsl:template match="test/infos">
	</xsl:template>

	<xsl:template match="test/shutdownlog">
	</xsl:template>

</xsl:stylesheet>

