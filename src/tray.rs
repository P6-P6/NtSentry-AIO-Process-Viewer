//! Notification-area icon: show the dashboard, scan now, exit. The icon turns
//! red while an alert is active. The same drawn icon is used for the window.

use eframe::egui;
use std::sync::mpsc::{Receiver, channel};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

pub const ICON_SIZE: u32 = 32;
const TOOLTIP: &str = "NtSentry AIO Process Viewer";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    Show,
    ScanNow,
    Exit,
}

/// A 32x32 RGBA disc with a light "T"; teal normally, red for an alert.
pub fn icon_rgba(alert: bool) -> Vec<u8> {
    let (r, g, b) = if alert { (205, 50, 45) } else { (25, 125, 140) };
    let size = ICON_SIZE as usize;
    let mut rgba = vec![0u8; size * size * 4];
    let center = (size as f32 - 1.0) / 2.0;
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 - center).powi(2) + (y as f32 - center).powi(2)).sqrt();
            let alpha = (15.0 - d).clamp(0.0, 1.0);
            if alpha == 0.0 {
                continue;
            }
            let letter = (8..=11).contains(&y) && (8..=23).contains(&x) || (14..=17).contains(&x) && (8..=24).contains(&y);
            let ring = d > 13.0;
            let (pr, pg, pb) = if letter {
                (245, 245, 245)
            } else if ring {
                (r / 2, g / 2, b / 2)
            } else {
                (r, g, b)
            };
            let i = (y * size + x) * 4;
            rgba[i..i + 4].copy_from_slice(&[pr, pg, pb, (alpha * 255.0) as u8]);
        }
    }
    rgba
}

pub fn window_icon() -> egui::IconData {
    egui::IconData { rgba: icon_rgba(false), width: ICON_SIZE, height: ICON_SIZE }
}

fn tray_image(alert: bool) -> Result<Icon, String> {
    Icon::from_rgba(icon_rgba(alert), ICON_SIZE, ICON_SIZE).map_err(|e| e.to_string())
}

pub struct Tray {
    icon: TrayIcon,
    actions: Receiver<TrayAction>,
    alert: Option<String>,
    // The menu items must outlive the tray icon.
    _items: Vec<MenuItem>,
}

impl Tray {
    /// Must be called on the UI thread, which runs the Windows message loop.
    pub fn new(ctx: &egui::Context) -> Result<Self, String> {
        let show = MenuItem::new("Show dashboard", true, None);
        let scan = MenuItem::new("Scan now", true, None);
        let exit = MenuItem::new("Exit", true, None);
        let menu = Menu::new();
        menu.append_items(&[&show, &scan, &PredefinedMenuItem::separator(), &exit]).map_err(|e| e.to_string())?;

        let (tx, actions) = channel();
        let ids = [(show.id().clone(), TrayAction::Show), (scan.id().clone(), TrayAction::ScanNow), (exit.id().clone(), TrayAction::Exit)];
        let (menu_tx, menu_ctx) = (tx.clone(), ctx.clone());
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some((_, action)) = ids.iter().find(|(id, _)| id == event.id()) {
                let _ = menu_tx.send(*action);
                menu_ctx.request_repaint();
            }
        }));
        let click_ctx = ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let show = matches!(
                event,
                TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
                    | TrayIconEvent::DoubleClick { button: MouseButton::Left, .. }
            );
            if show {
                let _ = tx.send(TrayAction::Show);
                click_ctx.request_repaint();
            }
        }));

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip(TOOLTIP)
            .with_icon(tray_image(false)?)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Tray { icon, actions, alert: None, _items: vec![show, scan, exit] })
    }

    pub fn poll(&self) -> Vec<TrayAction> {
        self.actions.try_iter().collect()
    }

    /// Red icon and the alert text as tooltip while an alert is active.
    pub fn set_alert(&mut self, alert: Option<&str>) {
        if self.alert.as_deref() == alert {
            return;
        }
        self.alert = alert.map(str::to_string);
        let _ = self.icon.set_icon(tray_image(alert.is_some()).ok());
        let tooltip = match alert {
            // Windows truncates tray tooltips at 127 characters.
            Some(a) => format!("ALERT: {}", a.chars().take(110).collect::<String>()),
            None => TOOLTIP.to_string(),
        };
        let _ = self.icon.set_tooltip(Some(tooltip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_is_a_round_32px_image() {
        let rgba = icon_rgba(false);
        assert_eq!(rgba.len(), 32 * 32 * 4);
        assert_eq!(rgba[3], 0, "corner is transparent");
        let center = (16 * 32 + 20) * 4;
        assert_eq!(rgba[center + 3], 255, "inside is opaque");
        assert_ne!(icon_rgba(true), rgba);
    }
}
