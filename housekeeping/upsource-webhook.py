#!/usr/bin/python3

import argparse
import json
import os
import requests
from flask import Flask, request

app = Flask(__name__)


class State:
    in_progress = "in_progress"
    failed = "failed"
    success = "success"


def submit_ci_status(key = "IROHA",
                     state = State.in_progress,
                     url = "null",
                     name = "null",
                     description = "null",
                     revision = "null"):
    upsource_url = "http://upsource.soramitsu.co.jp/~buildStatus"
    project = "iroha"

    post_body = {
        "key": key,
        "state": state,
        "url": url,
        "name": name,
        "description": description,
        "project": project,
        "revision": revision
    }

    # fails if token is not present
    TOKEN = os.environ["UPSOURCE_TOKEN"]

    post_headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "Authorization": "Basic {}".format(TOKEN)
    }

    r = requests.post(
        upsource_url,
        headers=post_headers,
        data=json.dumps(post_body)
    )

    print("status code: {}".format(r.status_code))



def process_json(parsed_json):
    options = {}

    try:
        pl = parsed_json["payload"]

        options["committer_login"] = pl["all_commit_details"][0]["committer_login"]
        options["commit"] = pl["all_commit_details"][0]["commit"]
        options["build_num"] = pl["build_num"]
        options["build_url"] = pl["build_url"]
        options["outcome"] = pl["outcome"]

        steps = pl["steps"]
        for step in steps:
            actions = step["actions"][0]
            if actions["failed"]: # not None
                options["failed_step"] = step["name"]

        return options
    except:
        return None


def prepare_key(s):
    return "IROHA-{}".format(s)

def prepare_state(s):
    return State.success if s == "success" else State.failed

def prepare_name(s):
    return str(s)

def prepare_description(s):
    return "By {}".format(s)

def in_progress_update():
    print('in progress update')
    try:
        # try to get these environment variables
        # throw, if at least one is missing
        build_num = str(os.environ["CIRCLE_BUILD_NUM"])
        build_url = str(os.environ["CIRCLE_BUILD_URL"])
        commit = os.environ["CIRCLE_SHA1"]
        username = os.environ["CIRCLE_USERNAME"]

        submit_ci_status(
            key=prepare_key(build_num),
            state=State.in_progress,
            url=build_url,
            name=build_num,
            description=prepare_name(username),
            revision=commit
        )

    except Exception as e:
        # just print exception and quit with no errcode
        print("exception occurred: {}".format(e))


@app.route("/", methods=['POST'])
def recv_json():
    try:
        if len(request.data) > 10 * 1024**2: # 10 MB
            return "request is too big"

        options = process_json(request.get_json())
        if not options:
            return "can not parse json body"

        submit_ci_status(
            key = prepare_key(options["build_num"]),
            state = prepare_state(options["outcome"]),
            url = options["build_url"],
            name = prepare_name(options["build_num"]),
            description = prepare_description(options["committer_login"]),
            revision = options["commit"]
        )

        return "ok"
    except Exception as e:
        return "error occurred: {}".format(e)

def main():
    parser = argparse.ArgumentParser(description='Update upsource CI status')
    parser.add_argument('--in-progress', action='store_true',
                        help='run script once in circle ci, notify upsource about "in progress" status of current commit')
    parser.add_argument('--server', dest='port',
                        help='run script as a server on specified interface and port. it processes failed/succeeded commits')

    args = parser.parse_args()
    if not args.port and not args.in_progress:
        print("use -h for help")
        exit(0)
    elif args.port:
        try:
            port = int(args.port)
        except:
            print("can not parse port")
            exit(1)

        app.run(host='0.0.0.0', port=port)
    elif args.in_progress:
        in_progress_update()

if __name__ == '__main__':
    main()
