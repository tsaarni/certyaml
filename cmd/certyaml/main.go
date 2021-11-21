// Copyright certyaml authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tsaarni/certyaml/internal/manifest"
)

const defaultManifest = "certs.yaml"

func main() {
	// destination directory for writing the created files
	var destination string

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-d destination] [certs.yaml]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Creates certificates and keys according to manifest file in YAML format.\n")
		fmt.Fprintf(os.Stderr, "By default it reads `certs.yaml` as a manifest file and creates files\n")
		fmt.Fprintf(os.Stderr, "in current directory.\n\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&destination, "d", "", "Short for --destination")
	flag.StringVar(&destination, "destination", "", "Destination directory where to create the certificates and keys")
	flag.Parse()

	manifestFile := defaultManifest
	if flag.Arg(0) != "" {
		manifestFile = flag.Arg(0)
	}
	stateFile := strings.TrimSuffix(manifestFile, filepath.Ext(manifestFile))
	stateFile = path.Join(destination, path.Base(stateFile)+".state")
	err := manifest.GenerateCertificates(manifestFile, stateFile, destination)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generating certificates failed: %s\n", err)
		os.Exit(1)
	}

}
