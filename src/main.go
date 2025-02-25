package main

import (
	"fmt"
	"keytab/keytab"
	"os"

	"github.com/p0dalirius/goopts/subparser"
)

var (
	mode  string
	debug bool

	keytabFile string
	principal  string
	password   string
	key        string
	outputFile string
	jsonOutput bool
	txtOutput  bool
	csvOutput  bool
)

func parseArgs() {
	asp := subparser.ArgumentsSubparser{
		Banner:          "keytab v1.0 - by Remi GASCOU (Podalirius)",
		Name:            "mode",
		Value:           &mode,
		CaseInsensitive: true,
	}

	// describe mode ============================================================================================================
	subparser_describe := asp.AddSubParser("describe", "Describe the content of a keytab file.")
	subparser_describe.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_describe.NewStringArgument(&keytabFile, "-f", "--keytab-file", "", false, "Path to the keytab file.")

	// add mode ============================================================================================================
	subparser_add := asp.AddSubParser("add", "Add a new key to the keytab file.")
	subparser_add.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_add.NewStringArgument(&keytabFile, "-f", "--keytab-file", "", false, "Path to the keytab file.")
	subparser_add.NewStringArgument(&principal, "-p", "--principal", "", false, "Principal to add to the keytab file.")
	subparser_add.NewStringArgument(&password, "-k", "--key", "", false, "Key to add to the keytab file.")
	subparser_add.NewStringArgument(&key, "-k", "--key", "", false, "Key to add to the keytab file.")

	// delete mode ============================================================================================================
	subparser_delete := asp.AddSubParser("delete", "Delete a key from the keytab file.")
	subparser_delete.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_delete.NewStringArgument(&keytabFile, "-f", "--keytab-file", "", false, "Path to the keytab file.")
	subparser_delete.NewStringArgument(&principal, "-p", "--principal", "", false, "Principal to delete from the keytab file.")

	// export mode ============================================================================================================
	subparser_export := asp.AddSubParser("export", "Export the keytab file to a file.")
	subparser_export.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")
	subparser_export.NewStringArgument(&keytabFile, "-f", "--keytab-file", "", false, "Path to the keytab file.")
	subparser_export.NewStringArgument(&outputFile, "-o", "--output-file", "", false, "Path to the output file.")
	subparser_export_group_format, err := subparser_export.NewRequiredMutuallyExclusiveArgumentGroup("Format")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_export_group_format.NewBoolArgument(&jsonOutput, "", "--json", false, "Export the keytab file in JSON format.")
		subparser_export_group_format.NewBoolArgument(&txtOutput, "", "--txt", false, "Export the keytab file in TXT format.")
		subparser_export_group_format.NewBoolArgument(&csvOutput, "", "--csv", false, "Export the keytab file in CSV format.")
	}

	asp.Parse()
}

func main() {
	parseArgs()

	if mode == "describe" {
		if _, err := os.Stat(keytabFile); err == nil {
			kt, err := keytab.LoadKeytabFromFile(keytabFile)
			if err != nil {
				fmt.Println("Error parsing keytab file:", err)
				return
			}
			kt.Describe(0)
		} else {
			fmt.Println("Keytab file does not exist.")
		}
	} else if mode == "add" {
		if _, err := os.Stat(keytabFile); err == nil {
			kt, err := keytab.LoadKeytabFromFile(keytabFile)
			if err != nil {
				fmt.Println("Error parsing keytab file:", err)
				return
			}

			kt.AddKey(principal, key, password)

			kt.SaveToFile(keytabFile)
		} else {
			fmt.Println("Keytab file does not exist.")
		}
	} else if mode == "delete" {
		if _, err := os.Stat(keytabFile); err == nil {
			kt, err := keytab.LoadKeytabFromFile(keytabFile)
			if err != nil {
				fmt.Println("Error parsing keytab file:", err)
				return
			}

			kt.DeleteKey(principal)

			kt.SaveToFile(keytabFile)
		} else {
			fmt.Println("Keytab file does not exist.")
		}
	} else if mode == "export" {
		if _, err := os.Stat(keytabFile); err == nil {
			kt, err := keytab.LoadKeytabFromFile(keytabFile)
			if err != nil {
				fmt.Println("Error parsing keytab file:", err)
				return
			}

			kt.Export(outputFile, jsonOutput, txtOutput, csvOutput)
		} else {
			fmt.Println("Keytab file does not exist.")
		}
	}
}
