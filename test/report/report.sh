#!/bin/sh
#
# file:        report.sh
# description: Generate a report with the results of the tests described
#              in the report.conf configuration file.
# author:      Didier Barvaux <didier.barvaux@b2i-toulouse.com>
#

debug=0

DIRNAME="`dirname $0`"
CONF="${DIRNAME}/report.conf"
LD_LIBRARY_PATH="${DIRNAME}/../../lib"
APP="${DIRNAME}/../test"

error=0

get_num_at_line()
{
	line="`echo \"$1\" | head -n $2 2>&1`"
	if [ $? -ne 0 ] ; then
		error=1
	fi

	line="`echo \"$line\" | tail -n 1 2>&1`"
	if [ $? -ne 0 ] ; then
		error=1
	fi

	num=`echo "$line" | sed -e 's|^[\t ]*<[^>]\+>\([^<]\+\)</[^>]\+>[\t ]*$|\1|' 2>&1`
	if [ $? -ne 0 ] ; then
		error=1
	elif [ "`echo \"$num\" | sed -e 's/[0-9]//g' 2>&1`" != "" ] ; then
		error=1
	fi

	if [ $error -eq 1 ] ; then
		return 0
	else
		return $num
	fi
}

print_result()
{
	html="$html\t\t\t\t<td"
	if [ "$1" != "PASS" ] ; then
		html="$html class=\"fail\"><a href=\"#$2\">$1</a>"
	else
		html="${html} class=\"pass\">$1"
	fi
	html="$html</td>\n"
}


html="<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml11.dtd\">\n"
html="$html<html>\n"
html="$html\t<head>\n"
html="$html\t\t<title>ROHC Test Results</title>\n"
html="$html\t\t<style>\n"
html="$html\t\t\ttable { border-collapse: collapse; }\n"
html="$html\t\t\ttd { border: black thin solid; padding: 0.5em; }\n"
html="$html\t\t\th2 { border-top: black thin solid; margin-top: 1em; padding-top: 1em; }\n"
html="$html\t\t\ttd.pass { color: green; }\n"
html="$html\t\t\ttd.fail { color: red; }\n"
html="$html\t\t\tdiv.optional { margin-left: 2em; }\n"
html="$html\t\t</style>\n"
html="$html\t</head>\n"
html="$html\t<body>\n"
html="$html\t\t<h1>ROHC Test Results</h1>\n"
html="$html\t\t<table>\n"
html="$html\t\t\t<tr>\n"
html="$html\t\t\t\t<td>Test name</td>\n"
html="$html\t\t\t\t<td>Compression process</td>\n"
html="$html\t\t\t\t<td>ROHC packets match reference packets</td>\n"
html="$html\t\t\t\t<td>Decompression process</td>\n"
html="$html\t\t\t\t<td>Decompressed packets match original ones</td>\n"
html="$html\t\t\t</tr>\n"

tests="`grep \"<test\" $CONF 2>&1`"
if [ $? -ne 0 ] ; then
	tests=""
fi

details=""
test_error=0
nb_lines=`echo -e "$tests" | wc -l`
i=1
while [ $i -le $nb_lines ] ; do

	line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"

	name="`echo \"$line\" | sed -e 's|^[\t ]*<test[\t ]\+name[\t ]*=[\t ]*"\([^"]\+\)"[\t ]\+dir[\t ]*=[\t ]*"\([^"]\+\)"[\t ]*/>[\t ]*$|\1|' 2>&1`"
	if [ $? -ne 0 ] ; then
		test_error=$(($test_error + 1))
		i=$(($i + 1))
		line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"
		continue
	elif [ "$name" = "$line" ] ; then
		test_error=$(($test_error + 1))
		i=$(($i + 1))
		line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"
		continue
	fi

	dir="`echo \"$line\" | sed -e 's|^[\t ]*<test[\t ]\+name[\t ]*=[\t ]*"\([^"]\+\)"[\t ]\+dir[\t ]*=[\t ]*"\([^"]\+\)"[\t ]*/>[\t ]*$|\2|' 2>&1`"
	if [ $? -ne 0 ] ; then
		test_error=$(($test_error + 1))
		i=$(($i + 1))
		line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"
		continue
	elif [ "$dir" = "$line" ] ; then
		test_error=$(($test_error + 1))
		i=$(($i + 1))
		line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"
		continue
	fi

	echo -n "Running test '$name'... "
	html="$html\t\t\t<tr>\n"
	html="$html\t\t\t\t<td>$name</td>\n"

	report="`$APP -c ${DIRNAME}/$dir/rohc.pcap ${DIRNAME}/$dir/source.pcap`"

	if [ $? -ne 0 ] ; then
		comp_result="FAIL"
		cmp_rohc_result="FAIL"
		decomp_result="FAIL"
		cmp_ip_result="FAIL"
	else
		logs_comp="`echo \"$report\" | xsltproc ${DIRNAME}/logs_comp.xsl - |  grep -v \"^<?xml\" | sed -e '/^\t*$/d'`"
		logs_cmp_rohc="`echo \"$report\" | xsltproc ${DIRNAME}/logs_cmp_rohc.xsl - |  grep -v \"^<?xml\" | sed -e '/^\t*$/d'`"
		logs_decomp="`echo \"$report\" | xsltproc ${DIRNAME}/logs_decomp.xsl - |  grep -v \"^<?xml\" | sed -e '/^\t*$/d'`"
		logs_cmp_ip="`echo \"$report\" | xsltproc ${DIRNAME}/logs_cmp_ip.xsl - |  grep -v \"^<?xml\" | sed -e '/^\t*$/d'`"

		if [ -z "$logs_comp" ] ; then
			comp_result="PASS"
		else
			comp_result="FAIL"
		fi

		if [ -z "$logs_cmp_rohc" ] ; then
			cmp_rohc_result="PASS"
		else
			cmp_rohc_result="FAIL"
		fi

		if [ -z "$logs_decomp" ] ; then
			decomp_result="PASS"
		else
			decomp_result="FAIL"
		fi

		if [ -z "$logs_cmp_ip" ] ; then
			cmp_ip_result="PASS"
		else
			cmp_ip_result="FAIL"
		fi
	fi

	print_result $comp_result "comp_details_$i"
	print_result $cmp_rohc_result "cmp_rohc_details_$i"
	print_result $decomp_result "decomp_details_$i"
	print_result $cmp_ip_result "cmp_ip_details_$i"
	html="$html\t\t\t</tr>\n"

	if [ "$comp_result" != "PASS" ] || [ "$cmp_rohc_result" != "PASS" ] || [ "$decomp_result" != "PASS" ] || [ "$cmp_ip_result" != "PASS" ] ; then

		details="$details\t\t<div>\n"
		details="$details\t\t\t<h2>Details about the '$name' test</h2>\n"

		if [ "$comp_result" != "PASS" ] ; then
			details="$details\t\t\t<div>\n"
			details="$details\t\t\t\t<h3><a name=\"comp_details_$i\">Details about the compression process</a></h3>\n"
			details="$details\n$logs_comp\n"
			details="$details\t\t\t</div>\n"
		fi

		if [ "$rohc_cmp_result" != "PASS" ] ; then
			details="$details\t\t\t<div>\n"
			details="$details\t\t\t\t<h3><a name=\"cmp_rohc_details_$i\">Details about the comparison between created ROHC packets and reference packets</a></h3>\n"
			details="$details\n$logs_cmp_rohc\n"
			details="$details\t\t\t</div>\n"
		fi

		if [ "$decomp_result" != "PASS" ] ; then
			details="$details\t\t\t<div>\n"
			details="$details\t\t\t\t<h3><a name=\"decomp_details_$i\">Details about the decompression process</a></h3>\n"
			details="$details\n$logs_decomp\n"
			details="$details\t\t\t</div>\n"
		fi

		if [ "$packets_result" != "PASS" ] ; then
			details="$details\t\t\t<div>\n"
			details="$details\t\t\t\t<h3><a name=\"cmp_ip_details_$i\">Details about the comparison between decompressed and original packets</a></h3>\n"
			details="$details\n$logs_cmp_ip\n"
			details="$details\t\t\t</div>\n"
		fi

		details="$details\t\t</div>\n\n\n"

	fi

	# go to next test
	i=$(($i + 1))
	line="`echo \"$tests\" | head -n $i 2>&1 | tail -n 1 2>&1`"

	echo "done."
done

# close the HTML table
html="$html\t\t</table>\n\n\n"

# print if some tests were not parsed correctly from the configuration file
if [ $test_error -gt 0 ] ; then
	echo "$test_error test(s) not parsed correctly"
	html="$html\t\t<div>$test_error test(s) not parsed correctly</div>\n"
fi

# add detailled information to the HTML page
html="${html}\n\n${details}"

# close the HTML page
html="$html\t</body>\n"
html="$html</html>\n"

# write the HTML page to the report.html file
echo -ne "$html" > ${DIRNAME}/report.html

echo "The report is available in the ${DIRNAME}/report.html HTML file."

# end of script
