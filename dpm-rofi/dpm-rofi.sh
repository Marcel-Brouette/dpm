#!/usr/bin/env bash

set -euo pipefail

# Dependencies: rofi, dpm (with kernel keyring support)
# Usage as Rofi modi: rofi -modi dpm:/path/to/rofi-dpm.sh -show dpm


# Fetch services from dpm list
# The output contains a header and then indented service names; extract robustly
list_services() {
	unbuffer dpm list | sed "1,3d;s/^    //g" || exit 1
}

# Prompt using rofi (dmenu mode) with custom styling
rofi_prompt() {
	local prompt="$1"
	rofi -dmenu -p "$prompt"
}

# Ask for password via rofi in password mode with custom styling
rofi_prompt_secret() {
	local prompt="$1"
	rofi -dmenu -password -p "$prompt" 
}

# Show message via rofi with custom anthracite theme
rofi_msg() {
	local message="$1"
	if command -v rofi >/dev/null 2>&1; then
		rofi -e "$message" -markup \
			-theme-str 'window { width: 700px; background-color: rgba(0, 0, 0, 0.9); }' \
			-theme-str 'textbox { background-color: #2d3748; color: #e2e8f0; padding: 20px; font: "JetBrains Mono 12"; }'
	fi
}

# Rofi modi mode: list services or generate password if service selected
modi_mode() {
	if ! command -v dpm >/dev/null 2>&1; then
		echo "dpm not found at dpm" >&2
		exit 1
	fi

	# If service is provided as argument, generate password
	if [ $# -eq 1 ] && [ -n "$1" ]; then
		local selection="$1"
		generate_password "$selection"
	else
		# Just list services
		local services
		if ! services=$(list_services); then
			echo "Unable to get services from dpm" >&2
			exit 1
		fi
		printf "%s\n" "$services"
	fi
}

# Format DPM output with colors and clean ANSI codes
format_dpm_output() {
	local output="$1"
	output=$(printf "%s" "$output" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r')
	output=$(echo "$output" | sed -re "s/\[SUCCESS\](.*)$/<span color='#4ade80' weight='bold'>\[SUCCESS\]\1<\/span>/g")
	output=$(echo "$output" | sed -re "s/\[ERROR\](.*)$/<span color='#f87171' weight='bold'>\[ERROR\]\1<\/span>/g")
	output=$(echo "$output" | sed -re "s/\[WARN\](.*)$/<span color='#fbbf24' weight='bold'>\[WARN\]\1<\/span>/g")
	echo "$output"
}

# Generate password for a service
generate_password() {
	local selection="$1"
	local output
	local master_key_needed=false
	local temp_file=$(mktemp)
	selection=$(printf "%q" "$selection")
	local gen_cmd=(dpm gen "$selection")
	
	if ! output=$(timeout 0.2 unbuffer "${gen_cmd[@]}" 2>&1); then
		# Timeout or error - check if master key needed
		if echo "$output" | grep -qi "\[ASK\]"; then
			local master
			master=$(printf "%q" "$master")
			master=$(rofi_prompt_secret "🔑 Master key") || exit 0
			[ -z "$master" ] && exit 0
			gen_cmd=(dpm gen -mp "$master" "$selection")
		fi
	fi
	
	"${gen_cmd[@]}" > "$temp_file" 2>&1
	output=$(cat "$temp_file")
	
	# Format and display output
	output=$(format_dpm_output "$output")
	
	shred "$temp_file" 2>/dev/null || true
	rm -f "$temp_file"
	
	rofi_msg "$output"
}

main() {

	bin_requirement=("cat" "mktemp" "unbuffer" "timeout" "dpm" "rofi")

	for bin in "${bin_requirement[@]}"
	do
		if ! command -v $bin &> /dev/null; then
			echo "[EXIT] $bin could not be found"
			exit 1
		fi 
	done

	local services
	if ! services=$(list_services); then
		rofi_msg "Unable to get services from dpm"
		exit 1
	fi

	local selection
	selection=$(printf "%s\n" "$services" | rofi_prompt "🔑 DPM") || exit 0
	[ -z "$selection" ] && exit 0

	# Generate password using the shared function
	generate_password "$selection"
}

main "$@"

# TODO: MODI MODE

#if [ -t 0 ] && [ -t 1 ]; then
	# Interactive terminal - run as standalone
#	main "$@"
#else
	# Not interactive (launched by Rofi) - run as modi
#	modi_mode "$@"
#fi

