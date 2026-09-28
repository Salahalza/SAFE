package tui_analyze

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var docStyle = lipgloss.NewStyle().Margin(1, 2)

type item struct {
	title, desc string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

type selectorModel struct {
	list     list.Model
	selected string
	quitting bool
}

func (m selectorModel) Init() tea.Cmd {
	return nil
}

func (m selectorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" || msg.String() == "esc" {
			m.quitting = true
			return m, tea.Quit
		}
		if msg.String() == "enter" {
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.selected = i.title
			}
			m.quitting = true
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m selectorModel) View() string {
	if m.quitting {
		return ""
	}
	return docStyle.Render(m.list.View())
}

// SelectCaseFolder launches an interactive TUI to pick a case folder.
// Searches current dir and ./test-output/host
func SelectCaseFolder() (string, error) {
	dirsToSearch := []string{".", filepath.Join("test-output", "host")}
	
	var items []list.Item

	for _, d := range dirsToSearch {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				// Only list folders that look like cases or contain metadata
				if _, err := os.Stat(filepath.Join(d, e.Name(), "case.json")); err == nil {
					items = append(items, item{title: filepath.Join(d, e.Name()), desc: "Case folder with case.json"})
				} else if len(e.Name()) > 5 && e.Name()[:5] == "CASE-" {
					items = append(items, item{title: filepath.Join(d, e.Name()), desc: "Case folder"})
				}
			}
		}
	}

	if len(items) == 0 {
		return "", fmt.Errorf("no case folders found in current directory or test-output/host")
	}

	m := selectorModel{list: list.New(items, list.NewDefaultDelegate(), 0, 0)}
	m.list.Title = "Select a SAFE Case Folder"

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return "", err
	}

	if m, ok := finalModel.(selectorModel); ok && m.selected != "" {
		return m.selected, nil
	}
	return "", nil
}
