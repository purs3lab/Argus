/**
 * @name LessDangerousSinks
 * @description Finding Less sinks
 * @kind path-problem
 * @tags security
 * @id javascipt/dangerous
 * @precision medium
 */

import javascript
import DataFlow::PathGraph

DataFlow::Node ioActionCalls() {
    result = DataFlow::moduleImport("@actions/io").getAMemberCall("rmRF").getArgument(0) 
}

DataFlow::Node addPathCalls() {
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("addPath").getAnArgument()
}

DataFlow::Node downloadToolCalls() {
    result = DataFlow::moduleImport("@actions/tool-cache").getAMemberCall("downloadTool").getArgument(0)
}

DataFlow::Node extract7zCalls() {
    result = DataFlow::moduleImport("@actions/tool-cache").getAMemberCall("extract7z").getArgument(0)
}

DataFlow::Node uploadArtifactsCalls() {
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(0) or
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(1) or
    result = DataFlow::moduleImport("@actions/artifact").getAMemberCall("uploadArtifact").getArgument(2)
}

DataFlow::Node fsCalls() {
    result = DataFlow::moduleImport("fs").getAMemberCall("write").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("write").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writeFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writeFile").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writev").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("writev").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("read").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("read").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("readFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("readFile").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("append").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("append").getArgument(1) or
    result = DataFlow::moduleImport("fs").getAMemberCall("appendFile").getArgument(0) or
    result = DataFlow::moduleImport("fs").getAMemberCall("appendFile").getArgument(1)
}

DataFlow::Node coreSources() { 
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getInput") or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("getMultilineInput")
}


class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "LessDangerousSinks"
    }

    override predicate isSource(DataFlow::Node source) {
        source = coreSources() 
    }

    override predicate isSink(DataFlow::Node sink) {
        sink = ioActionCalls() or
        sink = fsCalls() or 
        sink = addPathCalls() or
        sink = downloadToolCalls() or
        sink = extract7zCalls() or
        sink = uploadArtifactsCalls()

    }
}

from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, CallExpr e, Expr arg, string test
where cfg.hasFlowPath(source, sink) and
    e = source.getNode().asExpr() and
    arg = e.getArgument(0) and 
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, test

//from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
//where cfg.hasFlowPath(source, sink) 
//select source, sink, "issuehere"