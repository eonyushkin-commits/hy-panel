package atomicfile

import "os"

// Linux is the deployment target. Windows supports local development without
// pretending that Unix ownership or directory fsync can be verified there.
func preserveOwner(*os.File, os.FileInfo) error { return nil }
func syncDirectory(string) error                { return nil }
