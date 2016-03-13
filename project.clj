(defproject org.pupcus/authentication "0.0.2"

  :description "sandbar's authentication code factored out"

  :url "https://bitbucket.org/pupcus/authentication"

  :scm {:url "git@bitbucket.org:pupcus/authentication"}

  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}

  :dependencies [[ring "1.4.0"]
                 [slingshot "0.12.2"]
                 [org.pupcus/stateful-sessions "0.0.2"]]

  :profiles {:dev  {:resource-paths ["dev-resources"]
                    :dependencies [[org.clojure/clojure "1.8.0"]
                                   [org.slf4j/slf4j-log4j12 "1.7.5"]]}}

  :deploy-repositories [["snapshots"
                         {:url "https://clojars.org/repo"
                          :creds :gpg}]
                        ["releases"
                         {:url "https://clojars.org/repo"
                          :creds :gpg}]]

  :global-vars {*warn-on-reflection* true
                *assert* false})
