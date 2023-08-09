/**
 * @name Output Tainting Context
 * @description Finding Outputs Context
 * @kind path-problem
 * @tags security
 * @id javascipt/dangerous
 * @precision medium 
 */

import javascript
import DataFlow::PathGraph

DataFlow::Node outputSinks() {
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("setOutput").getArgument(1) or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("exportVariable").getArgument(1) or
    //result = DataFlow::moduleImport("@actions/core").getAMemberCall("setSecret").getArgument(0) or
    result = DataFlow::moduleImport("@actions/core").getAMemberCall("saveState").getArgument(1)
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

class Configuration extends TaintTracking::Configuration {
    Configuration() {
        this = "ContextOutput"
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
	    sink = outputSinks() 
    }
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink, string arg, string argname, string fname
where cfg.hasFlowPath(source, sink) and
    arg = source.getNode().asExpr().toString() and
    argname = sink.getNode().asExpr().getParent().(CallExpr).getArgument(0).getStringValue() and
    fname =  sink.getNode().asExpr().getParent().(CallExpr).getCalleeName()
select arg, source, sink, fname, argname