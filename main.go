// Copyright 2020 Tero Saarni
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

	"github.com/tsaarni/certyaml/pkg/certificate"
)

// destination directory for writing the created files
var destination string

// state stores the hash of the Certificate structs, in order to not re-create them unless manifest changed.
// state is persistently stored in state.yaml between executions
var state = make(map[string]string)

const defaultManifest = "certs.yaml"

func main() {
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

	manifestFilename := defaultManifest
	if flag.Arg(0) != "" {
		manifestFilename = flag.Arg(0)
	}

	// state file is stored along with the manifest (e.g. destdir/mypki.yaml -> destdir/mypki.state)
	stateFilename := strings.TrimSuffix(manifestFilename, filepath.Ext(manifestFilename))
	stateFilename = path.Join(destination, path.Base(stateFilename)+".state")

	fmt.Printf("Loading manifest file: %s\n", manifestFilename)

	err := certificate.GenerateCertficatesFromManifest(manifestFilename, stateFilename, destination)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generating certificates failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Writing state: %s\n", stateFilename)
}
