/**
 * @name Context Sinks
 * @description Finding sinks for context
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

DataFlow::Node pullrequestSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("head").getAPropertyRead("ref") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("head").getAPropertyRead("label") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("pull_request").getAPropertyRead("body")
}

DataFlow::Node issueSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("issue").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("issue").getAPropertyRead("body")
}

DataFlow::Node discussionSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("discussion").getAPropertyRead("title") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("discussion").getAPropertyRead("body")
}

DataFlow::Node commentSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("comment").getAPropertyRead("body") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("review").getAPropertyRead("body") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("review_comment").getAPropertyRead("body")
}

DataFlow::Node workflowRunSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_branch") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("email") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("workflow_run").getAPropertyRead("head_commit").getAPropertyRead("pull_requests").getAPropertyRead().getAPropertyRead("head").getAPropertyRead("ref") 
}

DataFlow::Node headCommitSources() {
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("head_commit").getAPropertyRead("author").getAPropertyRead("email") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("message") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("author").getAPropertyRead("name") or
    result = DataFlow::moduleImport("@actions/github").getAPropertyRead("context").getAPropertyRead("payload").getAPropertyRead("commits").getAPropertyRead().getAPropertyRead("author").getAPropertyRead("email") 
}



class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() {
        this = "LessContextSinks"
    }

    override predicate isSource(DataFlow::Node source) {
        source = pullrequestSources() or
        source = issueSources() or
        source = discussionSources() or
        source = workflowRunSources() or
        source = commentSources() or
        source = headCommitSources()
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

from MyConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, Expr arg, string test
where cfg.hasFlowPath(source, sink) and
    source.getNode().asExpr() = arg and
    test = sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, test
