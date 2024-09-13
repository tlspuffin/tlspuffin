if let Some(Source::Agent(agent_name)) = variable.query.source {
                        context.find_claim(agent_name, variable.typ)
                    } else {
                        todo!(Implement querying by label);
                    }
