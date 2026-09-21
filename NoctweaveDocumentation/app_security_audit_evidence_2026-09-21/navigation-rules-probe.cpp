#include "navigation_rules.h"
#include <cassert>
#include <iostream>

int main() {
    const std::vector<std::string> rules = {"^*", "views://mainview/index.html", "views://mainview/index.html#*"};
    for (const auto& url : {"views://mainview/index.html", "views://mainview/index.html#diagnostics"}) {
        assert(electrobun::checkNavigationRulesForUrl(rules, url));
    }
    for (const auto& url : {
        "https://attacker.invalid/", "http://127.0.0.1:9340/noctweb/", "file:///tmp/hostile.html",
        "data:text/html,<script>alert(1)</script>", "javascript:alert(1)", "about:blank",
        "views://mainview/hostile.html", "views://mainview/index.html/hostile", "views://mainview/index.html?redirect=evil",
        "views://mainview.attacker.invalid/index.html", "views://mainview@index.invalid/index.html",
        "views://mainview/index.html%23evil"
    }) {
        // The old default admitted these destinations; the app's policy must deny each one.
        assert(electrobun::checkNavigationRulesForUrl(std::vector<std::string>{}, url));
        assert(!electrobun::checkNavigationRulesForUrl(rules, url));
    }
    std::cout << "14 native navigation policy checks passed (2 allowed, 12 blocked).\n";
}
