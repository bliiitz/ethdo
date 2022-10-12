// Copyright © 2019 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	vault "github.com/bliiitz/go-eth2-wallet-store-vault"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	dirk "github.com/wealdtech/go-eth2-wallet-dirk"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	s3 "github.com/wealdtech/go-eth2-wallet-store-s3"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// SetupStore sets up the account store.
func SetupStore() error {

	if viper.GetString("remote") != "" {
		// We are using a remote account manager, so no local setup required.
		return nil
	}

	// Set up our wallet store.
	switch viper.GetString("store") {
	case "s3":

		if GetBaseDir() != "" {
			return errors.New("basedir does not apply to the s3 store")
		}
		store, err := s3.New(s3.WithPassphrase([]byte(GetStorePassphrase())))
		if err != nil {
			return errors.Wrap(err, "failed to access Amazon S3 wallet store")
		}
		if err := e2wallet.UseStore(store); err != nil {
			return errors.Wrap(err, "failed to use defined wallet store")
		}
		viper.Set("store", store)
	case "filesystem":
		opts := make([]filesystem.Option, 0)
		if GetStorePassphrase() != "" {
			opts = append(opts, filesystem.WithPassphrase([]byte(GetStorePassphrase())))
		}
		if GetBaseDir() != "" {
			opts = append(opts, filesystem.WithLocation(GetBaseDir()))
		}
		store := filesystem.New(opts...)
		if err := e2wallet.UseStore(store); err != nil {
			return errors.Wrap(err, "failed to use defined wallet store")
		}
		viper.Set("store", store)
	case "vault":
		opts := make([]vault.Option, 0)

		if GetStorePassphrase() != "" {
			opts = append(opts, vault.WithPassphrase([]byte(GetStorePassphrase())))
		}

		id := viper.GetString("id")
		if len(id) > 0 {
			opts = append(opts, vault.WithID([]byte(id)))
		}

		vault_addr := viper.GetString("vault_addr")
		if len(vault_addr) > 0 {
			opts = append(opts, vault.WithVaultAddr(vault_addr))
		}

		vault_auth := viper.GetString("vault_auth")
		if len(vault_auth) > 0 {
			opts = append(opts, vault.WithVaultAuth(vault_auth))
		}

		vault_token := viper.GetString("vault_token")
		if len(vault_token) > 0 {
			opts = append(opts, vault.WithVaultToken(vault_token))
		}

		vault_kubernetes_auth_role := viper.GetString("vault_kubernetes_auth_role")
		if len(vault_kubernetes_auth_role) > 0 {
			opts = append(opts, vault.WithVaultKubernetesAuthRole(vault_kubernetes_auth_role))
		}

		vault_kubernetes_auth_sa_token_path := viper.GetString("vault_kubernetes_auth_sa_token_path")
		if len(vault_kubernetes_auth_sa_token_path) > 0 {
			opts = append(opts, vault.WithVaultKubernetesAuthSATokenPath(vault_kubernetes_auth_sa_token_path))
		}

		vault_kubernetes_auth := viper.GetString("vault_kubernetes_auth")
		if len(vault_kubernetes_auth) > 0 {
			opts = append(opts, vault.WithVaultKubernetesAuth(vault_kubernetes_auth))
		}

		vault_secrets_mount_path := viper.GetString("vault_secrets_mount_path")
		if len(vault_secrets_mount_path) > 0 {
			opts = append(opts, vault.WithVaultSecretMountPath(vault_secrets_mount_path))
		}

		store, err := vault.New(opts...)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to access vault store"))
		}

		if err := e2wallet.UseStore(store); err != nil {
			return errors.Wrap(err, "failed to use defined wallet store")
		}
		viper.Set("store", store)
	default:
		return fmt.Errorf("unsupported wallet store %s", viper.GetString("store"))
	}

	return nil
}

// WalletFromInput obtains a wallet given the information in the viper variable
// "account", or if not present the viper variable "wallet".
func WalletFromInput(ctx context.Context) (e2wtypes.Wallet, error) {
	switch {
	case viper.GetString("account") != "":
		return WalletFromPath(ctx, viper.GetString("account"))
	case viper.GetString("wallet") != "":
		return WalletFromPath(ctx, viper.GetString("wallet"))
	default:
		return nil, errors.New("cannot determine wallet")
	}
}

// WalletFromPath obtains a wallet given a path specification.
func WalletFromPath(ctx context.Context, path string) (e2wtypes.Wallet, error) {
	walletName, _, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		return nil, err
	}
	if viper.GetString("remote") != "" {
		if viper.GetString("client-cert") == "" {
			return nil, errors.New("remote connections require client-cert")
		}
		if viper.GetString("client-key") == "" {
			return nil, errors.New("remote connections require client-key")
		}
		credentials, err := dirk.ComposeCredentials(ctx, viper.GetString("client-cert"), viper.GetString("client-key"), viper.GetString("server-ca-cert"))
		if err != nil {
			return nil, errors.Wrap(err, "failed to build dirk credentials")
		}

		endpoints, err := remotesToEndpoints([]string{viper.GetString("remote")})
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse remote servers")
		}

		return dirk.OpenWallet(ctx, walletName, credentials, endpoints)
	}
	wallet, err := e2wallet.OpenWallet(walletName)
	if err != nil {
		if strings.Contains(err.Error(), "failed to decrypt wallet") {
			return nil, errors.New("Incorrect store passphrase")
		}
		return nil, err
	}
	return wallet, nil
}

// WalletAndAccountFromInput obtains the wallet and account given the information in the viper variable "account".
func WalletAndAccountFromInput(ctx context.Context) (e2wtypes.Wallet, e2wtypes.Account, error) {
	return WalletAndAccountFromPath(ctx, viper.GetString("account"))
}

// WalletAndAccountFromPath obtains the wallet and account given a path specification.
func WalletAndAccountFromPath(ctx context.Context, path string) (e2wtypes.Wallet, e2wtypes.Account, error) {
	wallet, err := WalletFromPath(ctx, path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open wallet for account")
	}
	_, accountName, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain account name")
	}
	if accountName == "" {
		return nil, nil, errors.New("no account name")
	}

	if wallet.Type() == "hierarchical deterministic" && strings.HasPrefix(accountName, "m/") {
		if GetWalletPassphrase() == "" {
			return nil, nil, errors.New("walletpassphrase is required for direct path derivations")
		}

		locker, isLocker := wallet.(e2wtypes.WalletLocker)
		if isLocker {
			err = locker.Unlock(ctx, []byte(GetWalletPassphrase()))
			if err != nil {
				return nil, nil, errors.New("failed to unlock wallet")
			}
			defer relockAccount(locker)
		}
	}

	accountByNameProvider, isAccountByNameProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
	if !isAccountByNameProvider {
		return nil, nil, errors.New("wallet cannot obtain accounts by name")
	}
	account, err := accountByNameProvider.AccountByName(ctx, accountName)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain account")
	}
	return wallet, account, nil
}

// WalletAndAccountsFromPath obtains the wallet and matching accounts given a path specification.
func WalletAndAccountsFromPath(ctx context.Context, path string) (e2wtypes.Wallet, []e2wtypes.Account, error) {
	wallet, err := WalletFromPath(ctx, path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open wallet for account")
	}

	_, accountSpec, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain account specification")
	}
	if accountSpec == "" {
		accountSpec = "^.*$"
	} else {
		accountSpec = fmt.Sprintf("^%s$", accountSpec)
	}
	re := regexp.MustCompile(accountSpec)

	accounts := make([]e2wtypes.Account, 0)
	for account := range wallet.Accounts(ctx) {
		if re.Match([]byte(account.Name())) {
			accounts = append(accounts, account)
		}
	}

	// Tidy up accounts by name.
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Name() < accounts[j].Name()
	})

	return wallet, accounts, nil
}

// BestPublicKey returns the best public key for operations.
// It prefers the composite public key if present, otherwise the public key.
func BestPublicKey(account e2wtypes.Account) (e2types.PublicKey, error) {
	var pubKey e2types.PublicKey
	publicKeyProvider, isCompositePublicKeyProvider := account.(e2wtypes.AccountCompositePublicKeyProvider)
	if isCompositePublicKeyProvider {
		pubKey = publicKeyProvider.CompositePublicKey()
	} else {
		publicKeyProvider, isPublicKeyProvider := account.(e2wtypes.AccountPublicKeyProvider)
		if isPublicKeyProvider {
			pubKey = publicKeyProvider.PublicKey()
		} else {
			return nil, errors.New("account does not provide a public key")
		}
	}
	return pubKey, nil
}

// relockAccount locks an account; generally called as a defer after an account is unlocked so handles its own error.
func relockAccount(locker e2wtypes.AccountLocker) {
	if err := locker.Lock(context.Background()); err != nil {
		panic(err)
	}
}

// remotesToEndpoints generates endpoints from remote addresses.
func remotesToEndpoints(remotes []string) ([]*dirk.Endpoint, error) {
	endpoints := make([]*dirk.Endpoint, 0)
	for _, remote := range remotes {
		parts := strings.Split(remote, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid remote %q", remote)
		}
		port, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("invalid port in remote %q", remote))
		}
		endpoints = append(endpoints, dirk.NewEndpoint(parts[0], uint32(port)))
	}
	return endpoints, nil
}
