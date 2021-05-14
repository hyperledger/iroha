#!/bin/sh
set -e;

# Gets json entries from archived file
# Errors:
# Forcing 0 exit code is okay, as for now iroha sometimes doesn't write whole json object to file
get_entries() { lz4cat $1 2>/dev/null | jq -e '.duration = .duration.nanos / 1000000' || true; }

# Returns raw top $1 of items
json_top() { jq -s "[sort_by(.duration) | reverse[]] | .[range($1)]"; }

# Prints top $1 of items
top() {
	echo "|Function Name|id of future|Poll duration (in ms)|"
	echo "--------------------------------------------------"
	json_top $1 | jq -r '"|\(.name)|\(.id)|\(.duration)|"'
}

get_func() { jq -r "select(.name == \"$1\")"; }

mean() { jq -sr '[.[].duration] | add/length'; }
max()  { jq -sr '[.[].duration] | max'; }
min()  { jq -sr '[.[].duration] | min'; }

top_info() {
	echo "|Function Name|Max time|Average time|Min time|"
	echo "----------------------------------------------"
	json_top $1 <$2 | jq -r '.name' | sort | uniq | while read func; do
		MEAN=$(get_func $func <$2 | mean)
		MAX=$(get_func $func <$2 | max)
		MIN=$(get_func $func <$2 | min)
		printf "|%s|%s|%s|%s|\n" $func $MAX $MEAN $MIN
	done
}

get_entries $1 >raw_entries

echo "### Top 10 polls by time"
echo
top 10 <raw_entries
echo
echo
echo "### All functions from top 100 polls info"
echo
top_info 100 raw_entries

