using System.Runtime.CompilerServices;

// The isolated schema probe (fuzz/probe/SchemaProbe) compiles generated adapters against the internal RandomSchemaCase.
[assembly: InternalsVisibleTo("SchemaProbe")]
