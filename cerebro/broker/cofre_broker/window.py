"""Janela do cofre (tkinter): onde a pessoa digita senhas e valores, longe da conversa.

Um processo só guarda a sessão destravada: o do broker. A janela fala com ele pelo canal local
(autenticado); se não houver broker rodando, ela sobe um no próprio processo (e atende o canal,
para os MCPs e as sessões do Claude que vierem depois). O tkinter roda na thread principal; o que
fala com a rede vai para uma thread e volta pela fila (`after`).

O kit de recuperação aparece uma vez, depois de configurar, e some quando a pessoa marca
"guardei o kit". Os campos de senha e valor são mascarados e limpos depois do uso.
"""

from __future__ import annotations

import datetime as dt
import queue
import threading
import webbrowser
from collections.abc import Callable
from typing import Any

from .broker import CONFIRM_POLICIES, KINDS, VIAS, Broker, default_device_name
from .protocol import PASSWORD_MIN

BULLET = "•"


def check_new_password(first: str, second: str) -> str | None:
    """Motivo da recusa, ou None se a senha nova serve."""
    if len(first) < PASSWORD_MIN:
        return f"a senha do cofre precisa de pelo menos {PASSWORD_MIN} caracteres"
    if first != second:
        return "as duas senhas não são iguais"
    return None


def parse_destinations(text: str) -> list[dict[str, str]]:
    """`copiar, ambiente:curl, mcp:zabbix` → destinos da ferramenta (`via`, `target`)."""
    found = []
    for part in (p.strip() for p in text.replace(";", ",").split(",")):
        if not part:
            continue
        via, _, target = part.partition(":")
        if via.strip() not in VIAS:
            raise ValueError(f"via desconhecida: {via!r} (use {', '.join(VIAS)})")
        found.append({"via": via.strip(), "target": target.strip() or "*"})
    return found


def _when(ts: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(float(ts)).strftime("%d/%m %H:%M")
    except (TypeError, ValueError, OSError):
        return "-"


class VaultWindow:
    def __init__(self, root: Any, api: Any, *, local: bool) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk, self.root, self.api = tk, ttk, root, api
        self._queue: queue.Queue = queue.Queue()
        self._pair_polling = False
        root.title("Cofre do cérebro" + ("" if not local else " (broker nesta janela)"))
        root.geometry("820x560")
        self.status = tk.StringVar(value="…")
        ttk.Label(root, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(6, 0))
        tabs = ttk.Notebook(root)
        tabs.pack(fill="both", expand=True, padx=8, pady=8)
        self._build_state(tabs)
        self._build_pair(tabs)
        self._build_setup(tabs)
        self._build_entries(tabs)
        self._build_store(tabs)
        self._build_events(tabs)
        root.after(100, self._drain)
        self.refresh_state()

    # ---------- utilidades ----------

    def _async(self, job: Callable[[], Any], done: Callable[[Any], None] | None = None) -> None:
        def work() -> None:
            try:
                self._queue.put((done, job(), None))
            except Exception as exc:
                self._queue.put((done, None, exc))

        threading.Thread(target=work, daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                done, result, error = self._queue.get_nowait()
                if error is not None:
                    self.status.set(f"Erro: {error}")
                elif done is not None:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _frame(self, tabs: Any, title: str) -> Any:
        frame = self.ttk.Frame(tabs, padding=10)
        tabs.add(frame, text=title)
        return frame

    def _entry(self, parent: Any, label: str, row: int, *, secret: bool = False) -> Any:
        self.ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        entry = self.ttk.Entry(parent, width=48, show=BULLET if secret else "")
        entry.grid(row=row, column=1, sticky="we", pady=3)
        return entry

    def _take(self, entry: Any) -> str:
        """Lê e limpa um campo (senha ou valor não ficam no widget)."""
        text = entry.get()
        entry.delete(0, "end")
        return text

    # ---------- situação ----------

    def _build_state(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Situação")
        self.state_text = self.tk.Text(frame, height=12, width=90, state="disabled")
        self.state_text.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self.unlock_entry = self._entry(frame, "Senha do cofre:", 1, secret=True)
        self.unlock_entry.bind("<Return>", lambda e: self.unlock())
        buttons = self.ttk.Frame(frame)
        buttons.grid(row=2, column=0, columnspan=3, sticky="w", pady=6)
        self.ttk.Button(buttons, text="Destravar", command=self.unlock).pack(side="left")
        self.ttk.Button(buttons, text="Trancar", command=self.lock).pack(side="left", padx=6)
        self.ttk.Button(buttons, text="Atualizar", command=self.refresh_state).pack(side="left")

    def refresh_state(self) -> None:
        self._async(self.api.state, self._show_state)

    def _show_state(self, s: dict[str, Any]) -> None:
        lines = [f"{s['name']} {s['version']} · {s['platform']} · servidor {s['server']}"]
        lines.append(
            f"Aparelho: {s.get('device_name') or '-'} ({s.get('device')})"
            if s.get("paired")
            else "Aparelho: NÃO vinculado (aba Aparelho)"
        )
        lines.append(f"Chaves do aparelho: {s['keystore']}")
        if s.get("account"):
            lines.append(f"Conta no portal: {s['account']}")
        if s.get("keystore_warning"):
            lines.append(f"ALERTA: {s['keystore_warning']}")
        if s.get("error"):
            lines.append(f"Servidor: {s['error']}")
        elif s.get("paired"):
            if not s.get("configured"):
                lines.append("Cofre: ainda não configurado (aba Configurar)")
            else:
                lines.append(
                    f"Cofre: {'DESTRAVADO' if s.get('unlocked') else 'TRANCADO'}, "
                    f"{s.get('total', 0)} credencial(is)"
                )
        lines.append(f"Canal dos MCPs locais: {s['channel']}")
        self.state_text.configure(state="normal")
        self.state_text.delete("1.0", "end")
        self.state_text.insert("1.0", "\n".join(lines))
        self.state_text.configure(state="disabled")
        self.status.set("Destravado" if s.get("unlocked") else "Trancado")

    def unlock(self) -> None:
        password = self._take(self.unlock_entry)
        if not password:
            self.status.set("Digite a senha do cofre")
            return
        self.status.set("Destravando…")
        self._async(lambda: self.api.unlock(password=password), lambda r: self.refresh_state())

    def lock(self) -> None:
        self._async(self.api.lock, lambda r: self.refresh_state())

    # ---------- vincular aparelho ----------

    def _build_pair(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Aparelho")
        self.pair_name = self._entry(frame, "Nome do aparelho:", 0)
        self.pair_name.insert(0, default_device_name())
        self.pair_force = self.tk.BooleanVar(value=False)
        self.ttk.Checkbutton(
            frame, text="vincular de novo (já vinculado)", variable=self.pair_force
        ).grid(row=1, column=1, sticky="w")
        self.ttk.Button(frame, text="Vincular", command=self.pair).grid(row=2, column=1, sticky="w")
        self.pair_code = self.tk.StringVar()
        self.pair_link = ""
        self.pair_state = self.tk.StringVar()
        big = ("TkDefaultFont", 20, "bold")
        self.ttk.Label(frame, textvariable=self.pair_code, font=big).grid(row=3, column=1, pady=10)
        self.pair_prints = self.tk.StringVar()
        self.ttk.Label(
            frame, textvariable=self.pair_prints, font=("TkFixedFont", 13), justify="left"
        ).grid(row=6, column=1, sticky="w", pady=6)
        self.ttk.Button(
            frame,
            text="Abrir o portal no navegador",
            command=lambda: self.pair_link and webbrowser.open(self.pair_link),
        ).grid(row=4, column=1, sticky="w")
        self.ttk.Label(frame, textvariable=self.pair_state).grid(row=5, column=1, sticky="w")

    def pair(self) -> None:
        name, force = self.pair_name.get().strip(), self.pair_force.get()
        self._async(lambda: self.api.pair_start(name=name or None, force=force), self._paired)

    def _paired(self, started: dict[str, Any]) -> None:
        if started.get("already"):
            self.pair_state.set("Este aparelho já está vinculado. Marque 'vincular de novo'.")
            return
        self.pair_code.set(f"Código: {started['code']}")
        prints = started.get("fingerprints") or {}
        self.pair_prints.set(
            f"Impressão do servidor:     {prints.get('servidor', '?')}\n"
            f"Impressão deste aparelho:  {prints.get('aparelho', '?')}\n"
            "Aprove só se forem as mesmas que o portal mostra."
        )
        self.pair_link = started["link"]
        self.pair_state.set(f"Aprove no portal (logado, com MFA): {self.pair_link}")
        if started.get("new"):
            webbrowser.open(self.pair_link)
        if not self._pair_polling:
            self._pair_polling = True
            self.root.after(3000, self._poll_pair)

    def _poll_pair(self) -> None:
        def done(state: str) -> None:
            if state == "pendente":
                self.root.after(3000, self._poll_pair)
                return
            self._pair_polling = False
            self.pair_code.set("")
            self.pair_prints.set("")
            self.pair_state.set(
                "Aparelho vinculado. Agora configure (1ª vez) ou destrave o cofre."
                if state == "aprovado"
                else "O código venceu: clique em Vincular de novo."
            )
            self.refresh_state()

        self._async(self.api.pair_poll, done)

    # ---------- configurar ----------

    def _build_setup(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Configurar")
        self.ttk.Label(
            frame,
            wraplength=700,
            text=(
                f"Crie a senha do cofre (mínimo {PASSWORD_MIN} caracteres). Ela não sai deste "
                "aparelho e ninguém a recupera: o kit de recuperação, mostrado uma vez, é o único "
                "caminho se você a esquecer. Guarde-o longe do Claude (impresso ou num cofre seu)."
            ),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.setup_first = self._entry(frame, "Senha do cofre:", 1, secret=True)
        self.setup_second = self._entry(frame, "Repita a senha:", 2, secret=True)
        self.ttk.Button(frame, text="Configurar o cofre", command=self.setup).grid(
            row=3, column=1, sticky="w", pady=6
        )
        self.kit_text = self.tk.Text(
            frame, height=4, width=80, state="disabled", font=("TkFixedFont", 13)
        )
        self.kit_text.grid(row=4, column=0, columnspan=2, sticky="we", pady=6)
        self.kit_saved = self.tk.BooleanVar(value=False)
        self.kit_check = self.ttk.Checkbutton(
            frame,
            text="Guardei o kit em lugar seguro",
            variable=self.kit_saved,
            command=self._kit_toggle,
            state="disabled",
        )
        self.kit_check.grid(row=5, column=1, sticky="w")
        self.kit_close = self.ttk.Button(
            frame, text="Fechar o kit", command=self._kit_hide, state="disabled"
        )
        self.kit_close.grid(row=6, column=1, sticky="w")

    def setup(self) -> None:
        first, second = self._take(self.setup_first), self._take(self.setup_second)
        problem = check_new_password(first, second)
        if problem:
            self.status.set(problem)
            return
        self.status.set("Configurando (derivando a chave da senha)…")
        self._async(lambda: self.api.setup(password=first), self._kit_show)

    def _kit_show(self, kit: str) -> None:
        self.kit_text.configure(state="normal")
        self.kit_text.delete("1.0", "end")
        self.kit_text.insert("1.0", f"KIT DE RECUPERAÇÃO (aparece só agora):\n\n{kit}")
        self.kit_text.configure(state="disabled")
        self.kit_check.configure(state="normal")
        self.status.set("Cofre configurado e destravado. Guarde o kit antes de fechar.")
        self.refresh_state()

    def _kit_toggle(self) -> None:
        self.kit_close.configure(state="normal" if self.kit_saved.get() else "disabled")

    def _kit_hide(self) -> None:
        self.kit_text.configure(state="normal")
        self.kit_text.delete("1.0", "end")
        self.kit_text.configure(state="disabled")
        self.kit_saved.set(False)
        self.kit_check.configure(state="disabled")
        self.kit_close.configure(state="disabled")

    # ---------- credenciais ----------

    def _tree(self, parent: Any, columns: tuple[str, ...], widths: tuple[int, ...]) -> Any:
        tree = self.ttk.Treeview(parent, columns=columns, show="headings", height=14)
        for column, width in zip(columns, widths, strict=True):
            tree.heading(column, text=column)
            tree.column(column, width=width, anchor="w")
        tree.grid(row=1, column=0, columnspan=6, sticky="nsew")
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)
        return tree

    def _build_entries(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Credenciais")
        bar = self.ttk.Frame(frame)
        bar.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.show_archived = self.tk.BooleanVar(value=False)
        self.ttk.Checkbutton(
            bar,
            text="mostrar arquivadas",
            variable=self.show_archived,
            command=self.refresh_entries,
        ).pack(side="left")
        for text, command in (
            ("Atualizar", self.refresh_entries),
            ("Arquivar", self.archive),
            ("Restaurar", self.restore),
        ):
            self.ttk.Button(bar, text=text, command=command).pack(side="left", padx=4)
        self.entries = self._tree(
            frame,
            ("caminho", "tipo", "usuário", "versão", "destinos", "confirmação", "arquivada"),
            (220, 70, 110, 50, 200, 80, 60),
        )

    def refresh_entries(self) -> None:
        archived = self.show_archived.get()
        self._async(lambda: self.api.list_entries(archived=archived), self._show_entries)

    def _show_entries(self, entries: list[dict[str, Any]]) -> None:
        self.entries.delete(*self.entries.get_children())
        for e in entries:
            destinations = ", ".join(f"{d['via']}:{d['alvo']}" for d in e.get("destinos") or [])
            self.entries.insert(
                "",
                "end",
                iid=str(e["id"]),
                values=(
                    e["caminho"],
                    e.get("tipo"),
                    e.get("usuario", ""),
                    e.get("versao"),
                    destinations or "nenhum",
                    e.get("confirmacao"),
                    "sim" if e.get("arquivada") else "",
                ),
            )
        self.status.set(f"{len(entries)} credencial(is)")

    def _selected(self) -> str | None:
        found = self.entries.selection()
        if not found:
            self.status.set("Selecione uma credencial na lista")
            return None
        return str(found[0])

    def archive(self) -> None:
        ref = self._selected()
        if ref:
            self._async(lambda: self.api.archive(ref=ref), lambda r: self.refresh_entries())

    def restore(self) -> None:
        ref = self._selected()
        if ref:
            self._async(lambda: self.api.restore(ref=ref), lambda r: self.refresh_entries())

    # ---------- cadastrar, gerar, trocar valor ----------

    def _build_store(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Cadastrar")
        self.store_path = self._entry(frame, "Caminho (grupo/NOME):", 0)
        self.ttk.Label(frame, text="Tipo:").grid(row=1, column=0, sticky="w")
        self.store_kind = self.ttk.Combobox(frame, values=KINDS, state="readonly")
        self.store_kind.set("senha")
        self.store_kind.grid(row=1, column=1, sticky="w")
        self.store_user = self._entry(frame, "Usuário:", 2)
        self.store_url = self._entry(frame, "URL:", 3)
        self.store_dest = self._entry(frame, "Destinos (via:alvo, …):", 4)
        self.store_dest.insert(0, "digitar, copiar")
        self.ttk.Label(frame, text="Confirmação:").grid(row=5, column=0, sticky="w")
        self.store_confirm = self.ttk.Combobox(frame, values=CONFIRM_POLICIES, state="readonly")
        self.store_confirm.set("sempre")
        self.store_confirm.grid(row=5, column=1, sticky="w")
        self.store_value = self._entry(frame, "Valor:", 6, secret=True)
        self.store_generate = self.tk.BooleanVar(value=False)
        self.ttk.Checkbutton(
            frame, text="gerar senha forte (ninguém vê)", variable=self.store_generate
        ).grid(row=7, column=1, sticky="w")
        bar = self.ttk.Frame(frame)
        bar.grid(row=8, column=1, sticky="w", pady=8)
        self.ttk.Button(bar, text="Gravar nova", command=self.store).pack(side="left")
        self.ttk.Button(bar, text="Trocar o valor do caminho", command=self.replace).pack(
            side="left", padx=6
        )
        self.ttk.Label(
            frame,
            wraplength=640,
            text=(
                "Vias: digitar, copiar, ambiente:<comando> (o `run`), mcp:<consumidor> (outros "
                "MCPs). Sem destino, a credencial não é entregue a lugar nenhum. Confirmação: "
                "'sempre' pede o código do autenticador a cada uso, 'sessao' uma vez até trancar, "
                "'livre' não pede (intérprete e digitar pedem sempre)."
            ),
        ).grid(row=9, column=0, columnspan=2, sticky="w")

    def _value_args(self) -> dict[str, Any] | None:
        generate = self.store_generate.get()
        value = self._take(self.store_value)
        if not generate and not value:
            self.status.set("Digite o valor ou marque 'gerar senha forte'")
            return None
        return {"generate": True} if generate else {"value": value}

    def store(self) -> None:
        path = self.store_path.get().strip()
        try:
            destinations = parse_destinations(self.store_dest.get())
        except ValueError as exc:
            self.status.set(str(exc))
            return
        if not path:
            self.status.set("Diga o caminho (grupo/NOME)")
            return
        values = self._value_args()
        if values is None:
            return
        fields = {"usuario": self.store_user.get().strip(), "url": self.store_url.get().strip()}
        kind, confirm = self.store_kind.get(), self.store_confirm.get()
        self._async(
            lambda: self.api.store(
                path=path,
                kind=kind,
                fields=fields,
                confirm=confirm,
                destinations=destinations,
                **values,
            ),
            lambda r: (self.status.set(f"'{r['caminho']}' gravada"), self.refresh_entries()),
        )

    def replace(self) -> None:
        path = self.store_path.get().strip()
        if not path:
            self.status.set("Diga o caminho da credencial a trocar")
            return
        values = self._value_args()
        if values is None:
            return
        self._async(
            lambda: self.api.replace(ref=path, **values),
            lambda r: self.status.set(f"'{r['caminho']}' agora na versão {r['versao']}"),
        )

    # ---------- auditoria ----------

    def _build_events(self, tabs: Any) -> None:
        frame = self._frame(tabs, "Auditoria")
        self.ttk.Button(frame, text="Atualizar", command=self.refresh_events).grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        self.events = self._tree(
            frame, ("quando", "ação", "resultado", "detalhe"), (100, 110, 120, 420)
        )

    def refresh_events(self) -> None:
        self._async(lambda: self.api.events(limit=100), self._show_events)

    def _show_events(self, found: list[dict[str, Any]]) -> None:
        self.events.delete(*self.events.get_children())
        for e in found:
            self.events.insert(
                "",
                "end",
                values=(
                    _when(e.get("quando")),
                    e.get("acao"),
                    e.get("resultado"),
                    e.get("motivo") or "",
                ),
            )


def main() -> int:
    import tkinter as tk

    from . import tools as T
    from .channel import ChannelServer, find_remote

    api: Any = find_remote()
    channel = None
    if api is None:  # ninguém atende: o broker roda aqui, e esta janela atende o canal
        broker = Broker()
        channel = ChannelServer(broker, lambda n, a, cwd: T.call_tool(broker, n, a, cwd))
        channel.start()
        api = broker
    root = tk.Tk()
    VaultWindow(root, api, local=channel is not None)
    root.lift()
    root.attributes("-topmost", True)
    root.after(800, lambda: root.attributes("-topmost", False))
    root.focus_force()
    root.mainloop()
    if channel is not None:
        channel.stop()
    return 0
