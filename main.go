package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/chzyer/readline"
	"github.com/manifoldco/promptui"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	cr "github.com/obourdon/cloudresolver"
	"github.com/squarescale/sshcommand"
)

// Code to remove bell sound when using readline from promptui library
type stderr struct{}

func (s *stderr) Write(b []byte) (int, error) {
	if len(b) == 1 && b[0] == 7 {
		return 0, nil
	}
	return os.Stderr.Write(b)
}

func (s *stderr) Close() error {
	return os.Stderr.Close()
}

func init() {
	readline.Stdout = &stderr{}
}

func fallback() {
	syscall.Exec(viper.GetString("ssh"), os.Args, os.Environ())
}

func handleJump(args []string, provider string) []string {
	jh := viper.GetString(fmt.Sprintf("providers.%s.jumphost", provider))
	if jh == "" {
		log.Errorf("no jumphost specified")
		return args
	}
	r := cr.Resolvers[provider]
	if r == nil {
		log.Errorf("fallback: no resolver found for provider: %s", provider)
		return args
	}
	hosts, err := r.Resolve(jh, viper.AllSettings())
	if err != nil {
		log.Errorf(
			fmt.Sprintf(
				"Couldn't resolve host named \"%s\" with provider \"%s\", error: %s",
				jh,
				provider,
				err.Error(),
			),
		)
		return args
	}
	if len(hosts) == 0 {
		log.Errorf("resolution didn't returned any hosts")
		return args
	}

	ju := viper.GetString(fmt.Sprintf("providers.%s.jumpuser", provider))
	dest := hosts[0].Public
	if ju != "" {
		dest = fmt.Sprintf("%s@%s", ju, dest)
	}
	// Check if ssh version supports -J as a valid option
	cmd := exec.Command("ssh", "-J")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	matched, err := regexp.MatchString("option requires an argument", string(out))
	if err != nil {
		panic(err)
	}
	var ssh_args_str []string
	if matched {
		ssh_args_str = sshcommand.PrependOpt(args, []string{"-J", dest})
	} else {
		ssh_args_str = sshcommand.PrependOpt(args, []string{"-o", fmt.Sprintf("ProxyCommand ssh -W %%h:%%p %s", dest)})
	}
	log.Debugf("Adding ssh arguments: %#v", ssh_args_str)
	return ssh_args_str
}

//
// Function which tells if the input host matches
// the input filter given as a pair of strings [field_regex,value_regexp]
//
func hostMatch(f *cr.Host, filterstr []string) bool {
	// Use Golang reflection to walk over host structure
	val := reflect.ValueOf(f).Elem()
	// Parse all fields of structure
	for i := 0; i < val.NumField(); i++ {
		// Extract field value
		valueField := val.Field(i)
		// Extract field name and type
		typeField := val.Type().Field(i)
		// Deep trace
		log.Tracef("Field Name: %s,\t Field Value: %v\n", typeField.Name, valueField.Interface())
		// Check if field name matches field_regex
		matched1, err1 := regexp.MatchString(filterstr[0], strings.ToLower(typeField.Name))
		// Any error should be printed out (bad regexp, ...)
		if err1 != nil {
			log.Errorf("Error matching regexp %s: %#v", filterstr[0], err1)
		} else {
			// If field name matches, go on with field value checking
			if matched1 {
				// Deep trace
				log.Tracef("Field name: %s is matching %s", typeField.Name, filterstr[0])
				// Check if field value matches value_regex
				matched2, err2 := regexp.MatchString(filterstr[1], valueField.Interface().(string))
				// Any error should be printed out (bad regexp, ...)
				if err2 != nil {
					log.Errorf("Error matching regexp %s: %#v", filterstr[1], err2)
				} else {
					// If field value matches, return true
					if matched2 {
						// Better debug trace
						log.Debugf("Field value: %#v of field %s is matching %s", valueField.Interface(), typeField.Name, filterstr[1])
						return true
					} else {
						// Deep trace
						log.Tracef("Field value: %#v not matching %s", valueField.Interface(), filterstr[1])
					}
				}
			} else {
				// Deep trace
				log.Tracef("Field name: %s not matching %s", typeField.Name, filterstr[0])
			}
		}
	}
	// no match found
	return false
}

//
// Filter hosts based on given string criteria
// in the form field_regexp:value_regexp
//
func filterHosts(hosts []cr.Host, filter string) cr.Host {
	// Default return value is 1st host in list
	host := hosts[0]
	// No filter, return default value
	if filter == "" {
		return host
	}
	// Parse input filter string
	fitems := strings.Split(filter, ":")
	// Check filter syntax validity
	if len(fitems) != 2 {
		log.Errorf("Bad filter: %s (must be key_regexp:val_regexp)", filter)
		return host
	}
	// Initialize selected/matching host list to empty list
	shosts := []cr.Host{}
	// Loop over input hosts and add to list if they match
	for _, host := range hosts {
		if hostMatch(&host, fitems) {
			shosts = append(shosts, host)
		}
	}
	// No match, exit from program
	if len(shosts) == 0 {
		log.Errorf("No host matching filter: %s", filter)
		os.Exit(2)
	}
	// Multiple matches, exit from program
	if len(shosts) > 1 {
		log.Errorf("Multiple hosts matching filter: %s", filter)
		os.Exit(3)
	}
	// Return single selected/matching host
	host = shosts[0]
	log.Debugf("Connecting to host: %#v", host)
	return host
}

func selectHost(hosts []cr.Host, filter string) cr.Host {
	if !terminal.IsTerminal(syscall.Stdin) {
		return filterHosts(hosts, filter)
	}
	if viper.GetBool("interactive") {
		tmpls := promptui.SelectTemplates{
			Active:   `→  {{ .Id | cyan | bold }}`,
			Inactive: `   {{ .Id | cyan }}`,
			Selected: `{{ "✔" | green | bold }} {{ "Host" | bold }}: {{ .Id | cyan }}`,
			Details: `
instance name: {{ .InstanceName }}
provider: {{ .Provider   }}
region: {{ .Region     }}
zone: {{ .Zone       }}
id: {{ .Id         }}
private ipv4: {{ .PrivateIpv4}}
private ipv6: {{ .PrivateIpv6}}
private name: {{ .PrivateName}}
public ipv4: {{ .PublicIpv4 }}
public ipv6: {{ .PublicIpv6 }}
public name: {{ .PublicName }}`,
		}

		hostPrompt := promptui.Select{
			Label:     "Host",
			Items:     hosts,
			Templates: &tmpls,
		}

		idx, _, err := hostPrompt.Run()
		if err == nil {
			return hosts[idx]
		}
		log.Errorf("error in prompt: %s", err)
		os.Exit(1)
	}
	return filterHosts(hosts, filter)
}

var log = logrus.New()

func main() {
	viper.SetConfigName("hssh")
	viper.AddConfigPath("$HOME/.config")
	viper.SetEnvPrefix("HSSH")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("could not find config file")
	}

	if viper.GetBool("debug") {
		log.SetLevel(logrus.DebugLevel)
	}

	logfn := viper.GetString("logfile")
	if logfn != "" {
		logfile, err := os.OpenFile(logfn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			panic(fmt.Sprintf("couldn't open logfile: %s: %s", logfn, err))
		}
		log.SetOutput(logfile)
	} else {
		if !terminal.IsTerminal(syscall.Stdout) {
			log.SetOutput(ioutil.Discard)
		}
	}

	log.Debugf("starting hssh ...")

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		panic("could not find ssh neither in path nor in configuration")
	}
	log.Debugf("Using ssh command found at: %#v", ssh)
	viper.SetDefault("ssh", ssh)

	provider := viper.GetString("provider")
	if provider == "" {
		log.Warnf("fallback: no provider specified")
		fallback()
	}

	args := os.Args
	sc, err := sshcommand.New(args)
	if err != nil {
		log.Warnf("fallback: ssh command not parseable with args: %s", os.Args)
		fallback()
	}
	desthost := sc.Hostname()
	if desthost != viper.GetString(fmt.Sprintf("providers.%s.jumphost", provider)) {
		args = handleJump(os.Args, provider)
	}
	args[0] = viper.GetString("ssh")

	r := cr.Resolvers[provider]
	if r == nil {
		log.Warnf("fallback: no resolver found for provider: %s", provider)
		fallback()
	}

	hosts, err := r.Resolve(desthost, viper.AllSettings())
	if err != nil {
		log.Debugf(
			fmt.Sprintf(
				"Couldn't resolve host named \"%s\" with provider \"%s\", error: %s",
				desthost,
				provider,
				err.Error(),
			),
		)
	}
	if len(hosts) == 0 {
		log.Warnf("fallback: could not find any host matching destination %s", desthost)
		log.Warnf("%v", os.Args)
		log.Warnf("%v", viper.AllSettings())
		fallback()
	}

	host := selectHost(hosts, viper.GetString("filter"))
	hostname := host.Public
	if hostname == "" {
		hostname = host.Private
	}

	args = sshcommand.PrependOpt(args, []string{"-o", fmt.Sprintf("Hostname %s", hostname)})
	log.Debugf("executed command: %s", args)
	syscall.Exec(viper.GetString("ssh"), args, os.Environ())
}
