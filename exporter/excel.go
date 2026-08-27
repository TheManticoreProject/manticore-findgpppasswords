package exporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xuri/excelize/v2"
	"manticore-FindGPPPasswords/logger"

	"manticore-FindGPPPasswords/config"
	"manticore-FindGPPPasswords/gpp"
)

func GetExcelCellID(rowNumber int, columnNumber int) string {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	columnID := ""

	for columnNumber > 0 {
		remainder := columnNumber % 26
		if remainder == 0 {
			columnID = "Z" + columnID
			columnNumber = (columnNumber / 26) - 1
		} else {
			columnID = string(alphabet[remainder-1]) + columnID
			columnNumber = columnNumber / 26
		}
	}

	return columnID + fmt.Sprintf("%d", rowNumber)
}

func excelOutputPath(outputDir string, outputFile string) string {
	if outputFile == "" {
		return filepath.Join(outputDir, "GroupPolicyPasswords.xlsx")
	}
	if filepath.IsAbs(outputFile) {
		return filepath.Clean(outputFile)
	}
	return filepath.Join(outputDir, outputFile)
}

func GenerateExcel(gpppfound gpp.GroupPolicyPreferencePasswordsFound, config config.Config, outputFile string) {
	domain := strings.ToUpper(config.Credentials.Domain)

	if len(gpppfound.Entries) != 0 {
		pathToFile := excelOutputPath(config.OutputDir, outputFile)

		logger.Info(fmt.Sprintf("| Generating Excel file '%s'", pathToFile))

		// Create dir if not exists
		if _, err := os.Stat(pathToFile); os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(pathToFile), 0755); err != nil {
				fmt.Println(err)
			}
		}

		f := excelize.NewFile()
		defer f.Close()

		// Create styles
		styleHeader, err := f.NewStyle(
			&excelize.Style{
				Border: []excelize.Border{
					{Type: "left", Color: "000000", Style: 1},
					{Type: "top", Color: "000000", Style: 1},
					{Type: "bottom", Color: "000000", Style: 1},
					{Type: "right", Color: "000000", Style: 1},
				},
				Fill: excelize.Fill{
					Type:    "pattern",
					Color:   []string{"D3D3D3"},
					Pattern: 1,
				},
				Font: &excelize.Font{
					Bold: true,
				},
			},
		)
		if err != nil {
			if config.Debug {
				logger.Debug(fmt.Sprintf("Error creating styleHeader: %s", err))
			}
		}

		styleBorder, err := f.NewStyle(
			&excelize.Style{
				Border: []excelize.Border{
					{Type: "left", Color: "000000", Style: 1},
					{Type: "top", Color: "000000", Style: 1},
					{Type: "bottom", Color: "000000", Style: 1},
					{Type: "right", Color: "000000", Style: 1},
				},
			},
		)
		if err != nil {
			if config.Debug {
				logger.Debug(fmt.Sprintf("Error creating styleBorder: %s", err))
			}
		}

		// Create a new sheet.
		sheetIndex, err := f.NewSheet(domain)
		if err != nil {
			if config.Debug {
				logger.Debug(fmt.Sprintf("Error creating sheet: %s", err))
			}
		} else {
			// Create headers
			attributes := []string{"RunAs", "Username", "NewName", "Password", "Path"}
			for columnID, attr := range attributes {
				f.SetCellValue(domain, GetExcelCellID(1, columnID+1), attr)
				f.SetCellStyle(domain, GetExcelCellID(1, columnID+1), GetExcelCellID(1, columnID+1), styleHeader)
			}

			rowID := 2
			for path, cpasswordentries := range gpppfound.Entries {
				for _, cpasswordentry := range cpasswordentries {
					values := []string{
						cpasswordentry.RunAs,
						cpasswordentry.UserName,
						cpasswordentry.NewName,
						cpasswordentry.Password,
						path,
					}
					for columnID, value := range values {
						cellID := GetExcelCellID(rowID, columnID+1)
						f.SetCellValue(domain, cellID, value)
						f.SetCellStyle(domain, cellID, cellID, styleBorder)
					}
					rowID++
				}
			}

		}

		// Set active sheet of the workbook.
		f.SetActiveSheet(sheetIndex)
		// Save xlsx file by the given path.
		if err := f.SaveAs(pathToFile); err != nil {
			logger.Warn(fmt.Sprintf("Error saving file '%s': %s", pathToFile, err))
		}

		if config.Debug {
			logger.Info(fmt.Sprintf("| Successfully generated Excel file '%s'", filepath.Base(pathToFile)))
		}
	}
}
