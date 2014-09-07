<?xml version="1.0" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

	<!--
		  Copyright 2012 Didier Barvaux

		  This library is free software; you can redistribute it and/or
		  modify it under the terms of the GNU Lesser General Public
		  License as published by the Free Software Foundation; either
		  version 2.1 of the License, or (at your option) any later version.

		  This library is distributed in the hope that it will be useful,
		  but WITHOUT ANY WARRANTY; without even the implied warranty of
		  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
		  Lesser General Public License for more details.

		  You should have received a copy of the GNU Lesser General Public
		  License along with this library; if not, write to the Free Software
		  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
	-->

	<!-- XSL stylesheet to analyze valgrind memcheck XML report -->

	<xsl:output method="text" />

	<xsl:template match="valgrindoutput">
		<xsl:value-of select="count(error)" />
		<xsl:text>&#x0A;</xsl:text>
		<xsl:apply-templates select="error" />
	</xsl:template>

	<xsl:template match="error">
		<xsl:choose>
			<xsl:when test="kind = 'UninitCondition'">
				<xsl:value-of select="what" />
			</xsl:when>
			<xsl:when test="kind = 'Leak_DefinitelyLost'">
				<xsl:value-of select="xwhat/text" />
			</xsl:when>
			<xsl:when test="kind = 'InvalidRead'">
				<xsl:value-of select="what" />
			</xsl:when>
			<xsl:otherwise>
			 	<xsl:value-of select="xwhat/text" />
			</xsl:otherwise>
		</xsl:choose>
		<xsl:text>&#x0A;</xsl:text>
		<xsl:apply-templates select="stack" />
		<xsl:text>&#x0A;</xsl:text>
	</xsl:template>

	<xsl:template match="stack">
		<xsl:apply-templates select="frame" />
	</xsl:template>

	<xsl:template match="frame">
		<xsl:text>&#x09;</xsl:text>
		<xsl:if test="file != ''">
			<xsl:value-of select="file" />
			<xsl:text>:</xsl:text>
			<xsl:value-of select="line" />
			<xsl:text> </xsl:text>
		</xsl:if>
		<xsl:value-of select="fn" />
		<xsl:text>()</xsl:text>
		<xsl:text>&#x0A;</xsl:text>
	</xsl:template>

</xsl:stylesheet>
