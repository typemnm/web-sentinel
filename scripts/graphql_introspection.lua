-- GraphQL introspection exposure check
local endpoints = {"/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql"}
local query = "?query={__schema{types{name}}}"

for _, ep in ipairs(endpoints) do
    local resp = http.get(TARGET .. ep .. query)
    if resp.status == 200 and resp.body:find("__schema") then
        report.finding("high", "custom",
            "GraphQL Introspection Enabled: " .. ep,
            "Full schema is publicly queryable — exposes internal types, mutations, and queries.",
            TARGET .. ep
        )
        break
    end
end
